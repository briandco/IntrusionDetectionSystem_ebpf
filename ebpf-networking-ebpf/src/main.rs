#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_PIPE},              // Traffic Control action: let packet pass
    helpers::bpf_ktime_get_ns,      // Get kernel timestamp
    macros::{classifier, map},        // Macros for TC classifier and maps
    maps::{LruHashMap, PerfEventArray}, // BPF data structures
    programs::TcContext,              // Traffic Control context
};
use aya_log_ebpf::{info, warn};
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

/// Main tracking map: Key = (src_ip, time_bucket), Value = scan statistics
/// This is an LRU (Least Recently Used) map - old entries auto-expire
#[map]
static SCAN_TRACKER: LruHashMap<ScanKey,ScanInfo> = LruHashMap::with_max_entries(MAX_SCAN_ENTRIES, 0);

/// Communication channel to userspace - sends alerts when scans detected
#[map]
static EVENTS: PerfEventArray<ScanAlert> = PerfEventArray::new(0);

/// Port deduplication map: tracks which ports each IP has already tried
/// Key format: [src_ip:32][time_bucket:16][port:16]
#[map] 
static PORT_TRACKER: LruHashMap<u64, u32> = LruHashMap::with_max_entries(MAX_SCAN_ENTRIES * 10, 0);

//=============================================================================
// MAIN eBPF PROGRAM ENTRY POINT
//=============================================================================

/// This is the actual eBPF program that gets attached to the network interface
/// The #[classifier] macro tells Aya this is a TC (Traffic Control) program
#[classifier]
pub fn ebpf_networking(ctx: TcContext) -> i32 {
    match process_packet(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK,
    }
}

//=============================================================================
// PACKET PROCESSING LOGIC
//=============================================================================

fn process_packet(ctx: TcContext) -> Result<i32, ()> {
    // Step 1: Parse Ethernet Header
    let eth_hdr:EthHdr = ctx.load(0).map_err(|_|())?;
    
    // Only process IPv4 packets
    let eth_type = eth_hdr.ether_type;
    if eth_type != EtherType::Ipv4{
        return Ok(TC_ACT_OK);
    }
    
    // Parse IP Header
    let ip_hdr:Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_|())?;
    
    let src_addr = ip_hdr.src_addr;
    let proto = ip_hdr.proto;

    let src_ip = u32::from_be_bytes(src_addr);

    // Skip internal traffic (127.0.0.0/8)
    if (src_ip >> 24) == 127  {
        return Ok(TC_ACT_OK);
    }

    let dest_port = match proto{
        IpProto::Tcp => {
            let tcp_hdr:TcpHdr = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_|())?;
            let dest = tcp_hdr.dest;
            u16::from_be(dest)
        }

        IpProto::Udp => {
            let udp_hdr:UdpHdr = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_|())?;
            let dest = udp_hdr.dest;
            u16::from_be_bytes(dest)
        }
        _ => return Ok(TC_ACT_OK)
    };

    let now =unsafe {
        bpf_ktime_get_ns()
    };
    // Use u32 time bucket to match our ScanKey structure
    let time_bucket = ((now / 1_000_000_000) / SCAN_WINDOW_SECONDS) as u32;
    
    let scan_key = ScanKey{
        src_ip,
        time_bucket,
    };
    
      // Create port tracking key - pack efficiently into u64
    // Use lower 16 bits of time_bucket to save space
    let port_key = ((src_ip as u64) << 32) | 
                   (((time_bucket & 0xFFFF) as u64) << 16) | 
                   (dest_port as u64);

    // Check if this is a new port for this IP in this time window
    let is_new_port = match unsafe { PORT_TRACKER.get(&port_key) } {
        Some(_) => false,
        None => {
            // Ignore insertion errors - best effort tracking
            let _ = PORT_TRACKER.insert(&port_key, &1, 0);
            true
        }
    };

    // Update scan tracking
    match SCAN_TRACKER.get_ptr_mut(&scan_key) {
        Some(scan_info) => {
            unsafe {
                (*scan_info).total_attempts += 1;
                (*scan_info).last_seen = now;
                
                if is_new_port {
                    (*scan_info).unique_ports += 1;
                }

                // Check if this looks like a port scan
                if (*scan_info).unique_ports > PORT_SCAN_THRESHOLD {
                    let alert = ScanAlert {
                        src_ip,
                        unique_ports: (*scan_info).unique_ports,
                        total_attempts: (*scan_info).total_attempts,
                        time_window: time_bucket,
                    };

                    warn!(
                        &ctx,
                        "🚨 PORT SCAN DETECTED from {:i} - {} unique ports, {} attempts",
                        src_ip,
                        (*scan_info).unique_ports,
                        (*scan_info).total_attempts
                    );

                    let _ = EVENTS.output(&ctx, &alert, 0);
                }
            }
        }
        None => {
            let scan_info = ScanInfo {
                unique_ports: if is_new_port { 1 } else { 0 },
                total_attempts: 1,
                first_seen: now,
                last_seen: now,
            };

             // Ignore insertion errors - best effort tracking
            let _ = SCAN_TRACKER.insert(&scan_key, &scan_info, 0);
        }
    }

    Ok(TC_ACT_OK)
    
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
