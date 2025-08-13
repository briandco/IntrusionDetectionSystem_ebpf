//=============================================================================
// eBPF PORT SCAN DETECTION PROGRAM
//=============================================================================
// This eBPF program detects port scanning activities by monitoring network
// traffic and tracking connection attempts from individual IP addresses.
// It runs in kernel space and can process packets at very high speeds.

#![no_std]      // Don't use Rust's standard library (eBPF restriction)
#![no_main]     // No main function (eBPF programs use different entry points)

use aya_ebpf::{
    bindings::TC_ACT_OK,              // Traffic Control action: let packet pass
    helpers::bpf_ktime_get_ns,        // Get kernel timestamp in nanoseconds
    macros::{classifier, map},        // Macros for TC classifier and maps
    maps::{LruHashMap, PerfEventArray}, // BPF data structures
    programs::TcContext,              // Traffic Control context
};
use aya_log_ebpf::warn;               // Logging macro for eBPF
use network_types::{
    eth::{EthHdr, EtherType},         // Ethernet header parsing
    ip::{IpProto, Ipv4Hdr},          // IP protocol and IPv4 header
    tcp::TcpHdr,                     // TCP header
    udp::UdpHdr,                     // UDP header
};
use ebpf_networking_common::{         // Our shared data structures
    ScanAlert, ScanInfo, ScanKey, 
    MAX_SCAN_ENTRIES, PORT_SCAN_THRESHOLD, SCAN_WINDOW_SECONDS,
};

//=============================================================================
// BPF MAPS (Shared Data Structures)
//=============================================================================
// eBPF maps are key-value stores that can be shared between kernel and userspace.
// They persist data between packet processing events and enable communication
// with userspace applications.

/// Main tracking map: Key = (src_ip, time_bucket), Value = scan statistics
/// 
/// This LRU (Least Recently Used) map automatically evicts old entries when full.
/// - Key: ScanKey containing source IP and time bucket
/// - Value: ScanInfo containing scan statistics
/// - Purpose: Track scanning behavior per IP address per time window
/// - Size: Limited to MAX_SCAN_ENTRIES to prevent memory exhaustion
#[map]
static SCAN_TRACKER: LruHashMap<ScanKey, ScanInfo> = 
    LruHashMap::with_max_entries(MAX_SCAN_ENTRIES, 0);

/// Communication channel to userspace - sends alerts when scans detected
/// 
/// PerfEventArray is a high-performance ring buffer for sending data from
/// kernel to userspace. When a port scan is detected, an alert is sent
/// through this channel to notify monitoring applications.
#[map]
static EVENTS: PerfEventArray<ScanAlert> = PerfEventArray::new(0);

/// Port deduplication map: tracks which ports each IP has already tried
/// 
/// This map prevents counting the same port multiple times within a time window.
/// Key format: [src_ip:32bits][time_bucket:16bits][port:16bits] packed into u64
/// Value: dummy u32 (we only care about key existence)
/// Size: 10x larger than SCAN_TRACKER since we track individual ports
#[map] 
static PORT_TRACKER: LruHashMap<u64, u32> = 
    LruHashMap::with_max_entries(MAX_SCAN_ENTRIES * 10, 0);

//=============================================================================
// MAIN eBPF PROGRAM ENTRY POINT
//=============================================================================

/// Main eBPF program entry point - attached to network interface
/// 
/// The #[classifier] macro marks this as a TC (Traffic Control) classifier program.
/// TC programs can inspect, modify, or drop packets at the network layer.
/// 
/// Return values:
/// - TC_ACT_OK: Allow packet to continue normally
/// - TC_ACT_SHOT: Drop the packet (not used in this program)
/// 
/// @param ctx: Traffic Control context containing packet data and metadata
/// @return: Action to take on the packet (always TC_ACT_OK in this implementation)
#[classifier]
pub fn ebpf_networking(ctx: TcContext) -> i32 {
    // Wrap packet processing in error handling
    // If any error occurs during processing, default to allowing the packet
    match process_packet(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK,  // On error, allow packet to pass (fail open)
    }
}

//=============================================================================
// PACKET PROCESSING LOGIC
//=============================================================================

/// Core packet processing function - analyzes each packet for scan patterns
/// 
/// This function performs the main detection logic:
/// 1. Parses packet headers (Ethernet, IP, TCP/UDP)
/// 2. Extracts source IP and destination port
/// 3. Updates scan tracking statistics
/// 4. Detects and alerts on port scanning behavior
/// 
/// @param ctx: Traffic Control context containing packet data
/// @return: Result containing TC action or error
fn process_packet(ctx: TcContext) -> Result<i32, ()> {
    //-------------------------------------------------------------------------
    // STEP 1: PARSE ETHERNET HEADER
    //-------------------------------------------------------------------------
    
    // Load Ethernet header from packet start (offset 0)
    // ctx.load() safely reads packet data with bounds checking
    let eth_hdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    
    // Only process IPv4 packets - skip IPv6, ARP, etc.
    // This reduces processing overhead for irrelevant traffic
    let eth_type = eth_hdr.ether_type;
    if eth_type != EtherType::Ipv4 {
        return Ok(TC_ACT_OK);  // Allow non-IPv4 packets to pass
    }
    
    //-------------------------------------------------------------------------
    // STEP 2: PARSE IPv4 HEADER
    //-------------------------------------------------------------------------
    
    // Load IPv4 header (starts after Ethernet header)
    let ip_hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    
    // Extract source IP address and protocol
    let src_addr = ip_hdr.src_addr;  // Network byte order (big-endian)
    let proto = ip_hdr.proto;        // Protocol: TCP, UDP, ICMP, etc.

    // Convert source IP from network byte order to host byte order
    let src_ip = u32::from_be_bytes(src_addr);

    // Skip localhost traffic (127.0.0.0/8 network)
    // Port scans from localhost are usually legitimate testing
    if (src_ip >> 24) == 127 {
        return Ok(TC_ACT_OK);
    }

    //-------------------------------------------------------------------------
    // STEP 3: EXTRACT DESTINATION PORT (TCP/UDP ONLY)
    //-------------------------------------------------------------------------
    
    // Extract destination port based on protocol
    // Only TCP and UDP have port numbers - other protocols are ignored
    let dest_port = match proto {
        IpProto::Tcp => {
            // Load TCP header (after Ethernet + IPv4 headers)
            let tcp_hdr: TcpHdr = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| ())?;
            let dest = tcp_hdr.dest;  // Destination port in network byte order
            u16::from_be(dest)  // Convert to host byte order
        }

        IpProto::Udp => {
            // Load UDP header (after Ethernet + IPv4 headers)
            let udp_hdr: UdpHdr = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| ())?;
            let dest = udp_hdr.dest;  // Destination port in network byte order
            u16::from_be_bytes(dest)  // Convert to host byte order
        }
        
        // Ignore other protocols (ICMP, etc.) - they don't have ports
        _ => return Ok(TC_ACT_OK)
    };

    //-------------------------------------------------------------------------
    // STEP 4: TIME BUCKETING FOR SCAN DETECTION
    //-------------------------------------------------------------------------
    
    // Get current kernel time in nanoseconds
    let now = unsafe {
        bpf_ktime_get_ns()  // Unsafe because it's a BPF helper function
    };
    
    // Create time buckets to group scan attempts
    // Convert nanoseconds -> seconds -> time buckets
    // Example: if SCAN_WINDOW_SECONDS=60, each bucket represents 1 minute
    let time_bucket = ((now / 1_000_000_000) / SCAN_WINDOW_SECONDS) as u32;
    
    // Create key for scan tracking map
    // This uniquely identifies scan activity from a specific IP in a time window
    let scan_key = ScanKey {
        src_ip,
        time_bucket,
    };
    
    //-------------------------------------------------------------------------
    // STEP 5: PORT DEDUPLICATION
    //-------------------------------------------------------------------------
    
    // Create efficient packed key for port tracking
    // Format: [src_ip:32][time_bucket:16][port:16] = 64 bits total
    // We only use lower 16 bits of time_bucket to save space
    let port_key = ((src_ip as u64) << 32) |                    // Upper 32 bits: source IP
                   (((time_bucket & 0xFFFF) as u64) << 16) |    // Middle 16 bits: time bucket
                   (dest_port as u64);                          // Lower 16 bits: destination port

    // Check if this IP has already tried this port in this time window
    // This prevents counting duplicate attempts to the same port
    let is_new_port = match unsafe { PORT_TRACKER.get(&port_key) } {
        Some(_) => false,  // Port already seen - not a new port
        None => {
            // First time seeing this port - mark it as seen
            // Use best-effort insertion (ignore errors to avoid blocking traffic)
            let _ = PORT_TRACKER.insert(&port_key, &1, 0);
            true  // This is a new port for this IP
        }
    };

    //-------------------------------------------------------------------------
    // STEP 6: UPDATE SCAN STATISTICS
    //-------------------------------------------------------------------------
    
    // Try to get existing scan info for this IP/time_bucket
    match SCAN_TRACKER.get_ptr_mut(&scan_key) {
        Some(scan_info) => {
            // Existing scan info found - update statistics
            unsafe {
                // Always increment total attempts
                (*scan_info).total_attempts += 1;
                
                // Update last seen timestamp
                (*scan_info).last_seen = now;
                
                // Only increment unique ports if this is a new port
                if is_new_port {
                    (*scan_info).unique_ports += 1;
                }

                //-------------------------------------------------------------
                // STEP 7: SCAN DETECTION AND ALERTING
                //-------------------------------------------------------------
                
                // Check if behavior indicates port scanning
                // Threshold based on number of unique ports attempted
                if (*scan_info).unique_ports > PORT_SCAN_THRESHOLD {
                    // Create alert structure for userspace notification
                    let alert = ScanAlert {
                        src_ip,
                        unique_ports: (*scan_info).unique_ports,
                        total_attempts: (*scan_info).total_attempts,
                        time_window: time_bucket,
                    };

                    // Log warning message (visible in kernel logs / trace_pipe)
                    // {:i} is a special format for IP addresses in eBPF
                    warn!(
                        &ctx,
                        "🚨 PORT SCAN DETECTED from {:i} - {} unique ports, {} attempts",
                        src_ip,
                        (*scan_info).unique_ports,
                        (*scan_info).total_attempts
                    );

                    // Send alert to userspace via perf event array
                    // Userspace monitoring tools can read these alerts
                    let _ = EVENTS.output(&ctx, &alert, 0);
                }
            }
        }
        
        None => {
            // No existing scan info - create new entry
            let scan_info = ScanInfo {
                unique_ports: if is_new_port { 1 } else { 0 },  // Count this port if new
                total_attempts: 1,                              // First attempt
                first_seen: now,                                // Record start time
                last_seen: now,                                 // Same as first time
            };

            // Insert new scan info into tracking map
            // Use best-effort insertion (ignore errors to avoid blocking traffic)
            let _ = SCAN_TRACKER.insert(&scan_key, &scan_info, 0);
        }
    }

    // Always allow the packet to continue (we're monitoring, not blocking)
    Ok(TC_ACT_OK)
}

//=============================================================================
// eBPF RUNTIME REQUIREMENTS
//=============================================================================

/// Panic handler for eBPF programs
/// 
/// eBPF programs cannot use the standard panic handler, so we provide
/// a simple implementation that just loops forever. In practice, the
/// eBPF verifier should prevent panics from occurring.
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}  // Infinite loop - program will be terminated by kernel
}

/// License declaration required by eBPF verifier
/// 
/// The eBPF verifier requires programs to declare their license.
/// "Dual MIT/GPL" allows the program to be used under either license.
/// This is stored in a special ELF section that the verifier reads.
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";