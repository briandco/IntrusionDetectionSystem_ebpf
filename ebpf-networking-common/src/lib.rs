//=============================================================================
// eBPF NETWORKING COMMON DEFINITIONS
//=============================================================================
// This module contains shared data structures and constants used by both
// the eBPF kernel program and userspace applications for port scan detection.
// It ensures consistent data layout and communication protocols between
// kernel and userspace components.

#![no_std]  // No standard library - works in both kernel (eBPF) and userspace

//=============================================================================
// DETECTION PARAMETERS & CONSTANTS
//=============================================================================

/// Time window for port scan detection (60 seconds)
/// 
/// This creates temporal "buckets" that group network activity together.
/// All connection attempts within this window are analyzed as a group.
/// 
/// Example: If an IP scans ports at timestamps 100, 130, and 150 seconds,
/// and SCAN_WINDOW_SECONDS = 60, then:
/// - Timestamps 100 and 130 fall in the same bucket (bucket 1: 60-119s)  
/// - Timestamp 150 falls in the next bucket (bucket 2: 120-179s)
/// 
/// Tuning considerations:
/// - Larger windows: Catch slow/distributed scans, but may miss rapid scans
/// - Smaller windows: Catch rapid scans, but may miss coordinated slow scans
pub const SCAN_WINDOW_SECONDS: u64 = 60;

/// Threshold for port scan detection
/// 
/// If a single IP address attempts to connect to more than this many
/// unique ports within one time window, it's classified as a port scan.
/// 
/// This threshold balances detection sensitivity:
/// - Too low (e.g., 3): Many false positives from legitimate multi-service apps
/// - Too high (e.g., 50): May miss actual scans that target fewer ports
/// 
/// Value of 10 is chosen because:
/// - Normal applications rarely connect to >10 services simultaneously
/// - Most port scanners probe 10+ ports to map network topology
/// - Provides good balance between detection and false positives
pub const PORT_SCAN_THRESHOLD: u32 = 10;

/// Maximum entries in our BPF hash maps
/// 
/// This prevents memory exhaustion in the kernel by limiting map sizes.
/// When maps reach this limit, older entries are automatically evicted
/// using LRU (Least Recently Used) policy.
/// 
/// Memory usage estimation:
/// - SCAN_TRACKER: 10,000 × (8 bytes key + 24 bytes value) = ~320KB
/// - PORT_TRACKER: 100,000 × (8 bytes key + 4 bytes value) = ~1.2MB
/// - Total: ~1.5MB per map set
/// 
/// Tuning considerations:
/// - Larger values: Better tracking of distributed/slow scans
/// - Smaller values: Lower memory usage, but may miss some attacks
pub const MAX_SCAN_ENTRIES: u32 = 10000;

//=============================================================================
// BPF MAP KEY STRUCTURES
//=============================================================================
// These structures serve as keys in BPF hash maps. Keys must be:
// 1. Fixed size (no dynamic allocation in eBPF)
// 2. Consistent memory layout between kernel and userspace
// 3. Efficient for hashing and comparison operations

/// Key for tracking scan attempts per source IP per time window
/// 
/// This structure uniquely identifies scan activity from a specific
/// IP address within a specific time bucket. It serves as the primary
/// key for the SCAN_TRACKER map.
/// 
/// Memory layout (8 bytes total):
/// [src_ip: 32 bits][time_bucket: 32 bits]
/// 
/// Design rationale:
/// - Combines IP and time to create unique tracking windows
/// - Fixed size enables efficient BPF map operations
/// - Time bucketing allows automatic cleanup of old data
#[repr(C)]  // C representation ensures consistent memory layout across platforms
#[derive(Clone, Copy)]  // Enable efficient copying for BPF operations
pub struct ScanKey {
    /// Source IP address in host byte order (u32)
    /// 
    /// Stored as u32 for efficient comparison and hashing.
    /// Example: 192.168.1.100 = 0xC0A80164 in hex
    pub src_ip: u32,
    
    /// Time bucket identifier
    /// 
    /// Calculated as: (current_timestamp / SCAN_WINDOW_SECONDS)
    /// This creates discrete time windows for grouping activity.
    /// 
    /// Example with 60-second windows:
    /// - Timestamp 0-59s   → bucket 0
    /// - Timestamp 60-119s → bucket 1
    /// - Timestamp 120-179s → bucket 2
    pub time_bucket: u32,
}

/// Enable this structure to work with Aya BPF library (userspace only)
/// 
/// The Pod trait indicates this is Plain Old Data - safe to transmit
/// between kernel and userspace as raw bytes without serialization.
#[cfg(feature = "user")]
unsafe impl aya::Pod for ScanKey {}

//=============================================================================
// BPF MAP VALUE STRUCTURES
//=============================================================================

/// Information tracked about each potential scanner
/// 
/// This structure stores comprehensive statistics about scanning behavior
/// from each IP address within each time window. It enables sophisticated
/// detection logic beyond simple port counting.
/// 
/// Memory layout (24 bytes total):
/// [unique_ports: 32][total_attempts: 32][first_seen: 64][last_seen: 64]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ScanInfo {
    /// Number of unique destination ports this IP has attempted
    /// 
    /// This is the primary metric for scan detection. Only counts
    /// each port once per time window, regardless of retry attempts.
    /// 
    /// Examples:
    /// - Normal web browsing: 1-3 ports (80, 443, maybe 8080)
    /// - Port scan: 10+ ports (22, 23, 80, 135, 443, 445, etc.)
    pub unique_ports: u32,
    
    /// Total connection attempts (can be > unique_ports with retries)
    /// 
    /// Counts every connection attempt, including retries to same ports.
    /// Useful for detecting aggressive vs. stealthy scanning patterns.
    /// 
    /// Pattern analysis:
    /// - High ratio (total >> unique): Aggressive scanner with retries
    /// - Low ratio (total ≈ unique): Stealthy scanner, single attempts
    pub total_attempts: u32,
    
    /// Timestamp when we first saw this IP in this time window (nanoseconds)
    /// 
    /// Enables calculation of scan duration and velocity metrics.
    /// Stored as kernel timestamp from bpf_ktime_get_ns().
    /// 
    /// Uses:
    /// - Calculate scan duration: last_seen - first_seen
    /// - Detect burst vs. distributed scanning patterns
    /// - Timeline reconstruction for forensics
    pub first_seen: u64,
    
    /// Timestamp of the most recent activity from this IP (nanoseconds)
    /// 
    /// Updated on every new connection attempt. Used for:
    /// - LRU map cleanup decisions
    /// - Detecting ongoing vs. completed scans
    /// - Activity timeline reconstruction
    pub last_seen: u64,
}

/// Enable userspace access via Aya BPF library
#[cfg(feature = "user")]
unsafe impl aya::Pod for ScanInfo {}

//=============================================================================
// ALERT STRUCTURE (eBPF → Userspace Communication)
//=============================================================================

/// Alert sent from eBPF to userspace when port scan is detected
/// 
/// This structure is transmitted through a BPF perf event array when
/// scanning behavior exceeds the detection threshold. It provides
/// userspace applications with essential information for response.
/// 
/// Communication flow:
/// 1. eBPF program detects scan (unique_ports > PORT_SCAN_THRESHOLD)
/// 2. Creates ScanAlert structure with current statistics  
/// 3. Sends via EVENTS.output() to userspace
/// 4. Userspace monitoring tool receives and processes alert
/// 
/// Memory layout (16 bytes total):
/// [src_ip: 32][unique_ports: 32][total_attempts: 32][time_window: 32]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ScanAlert {
    /// IP address of the scanning host (host byte order)
    /// 
    /// The source IP that triggered the scan detection.
    /// Userspace can use this for:
    /// - Logging and alerting
    /// - Automatic blocking/rate limiting
    /// - Threat intelligence correlation
    /// - Geolocation and reputation lookups
    pub src_ip: u32,
    
    /// Number of unique ports scanned when alert was triggered
    /// 
    /// This will be > PORT_SCAN_THRESHOLD when alert is sent.
    /// Indicates the scope/severity of the scanning activity.
    /// 
    /// Severity classification examples:
    /// - 11-20 ports: Low severity (possible reconnaissance)
    /// - 21-100 ports: Medium severity (systematic scanning)  
    /// - 100+ ports: High severity (comprehensive scan)
    pub unique_ports: u32,
    
    /// Total connection attempts when alert was triggered
    /// 
    /// Provides context about scan aggressiveness:
    /// - attempts ≈ unique_ports: Single attempt per port (stealthy)
    /// - attempts >> unique_ports: Multiple attempts (aggressive/noisy)
    pub total_attempts: u32,
    
    /// Time bucket when scan was detected
    /// 
    /// Identifies which time window contained the scanning activity.
    /// Userspace can correlate with other events and calculate
    /// absolute timestamps if needed.
    /// 
    /// Calculation: timestamp = time_window × SCAN_WINDOW_SECONDS
    pub time_window: u32,
}

/// Enable userspace access via Aya BPF library
#[cfg(feature = "user")]
unsafe impl aya::Pod for ScanAlert {}

//=============================================================================
// ALTERNATIVE KEY STRUCTURE (Currently Commented Out)
//=============================================================================
// Alternative approach for port tracking using a structured key instead
// of the packed u64 approach used in the main program.
//
// #[repr(C)]
// #[derive(Clone, Copy)]
// pub struct PortKey {
//     /// Source IP address
//     pub src_ip: u32,
//     
//     /// Time bucket (truncated to u32 for space efficiency)
//     /// Still provides 136+ years of time range at 1-second resolution
//     pub time_bucket: u32,
//     
//     /// Destination port being accessed
//     pub dest_port: u16,
//     
//     /// Explicit padding to ensure proper memory alignment
//     /// Without this, the compiler might add padding anyway,
//     /// but explicit padding ensures consistent layout
//     pub _padding: u16,
// }
//
// This structured approach has trade-offs vs. the packed u64:
// Pros: More readable, type-safe field access
// Cons: 12 bytes vs 8 bytes (50% larger), potential alignment issues

//=============================================================================
// HELPER CONSTANTS FOR ENHANCED DETECTION
//=============================================================================

/// Well-known service ports commonly targeted by scanners
/// 
/// This array contains ports that are frequently targeted during
/// network reconnaissance and attack attempts. Scanning these ports
/// is more suspicious than scanning random high-numbered ports.
/// 
/// Categories included:
/// - Remote access: SSH(22), Telnet(23), RDP(3389)
/// - Web services: HTTP(80), HTTPS(443)
/// - File sharing: FTP(21), SMB(445), NetBIOS(139)
/// - Email: SMTP(25), POP3(110), IMAP(143)
/// - Databases: MySQL(3306), PostgreSQL(5432), MongoDB(27017)
/// - Other services: DNS(53), RPC(135), Redis(6379)
/// 
/// Usage: Can be used to weight detection scores - hits on these
/// ports could increase suspicion level even below the threshold.
pub const INTERESTING_PORTS: &[u16] = &[
    21,    // FTP (File Transfer Protocol) - often misconfigured
    22,    // SSH (Secure Shell) - prime target for brute force
    23,    // Telnet - insecure, often left enabled by mistake  
    25,    // SMTP (Simple Mail Transfer Protocol) - email relay abuse
    53,    // DNS (Domain Name System) - infrastructure reconnaissance
    80,    // HTTP (Hypertext Transfer Protocol) - web services
    110,   // POP3 (Post Office Protocol) - email access
    135,   // RPC (Remote Procedure Call) - Windows services
    139,   // NetBIOS Session Service - Windows file sharing
    143,   // IMAP (Internet Message Access Protocol) - email access
    443,   // HTTPS (HTTP Secure) - encrypted web services
    445,   // SMB (Server Message Block) - Windows file sharing
    993,   // IMAPS (IMAP over SSL) - secure email access
    995,   // POP3S (POP3 over SSL) - secure email access
    1433,  // Microsoft SQL Server - database access
    3306,  // MySQL - database access
    3389,  // RDP (Remote Desktop Protocol) - Windows remote access
    5432,  // PostgreSQL - database access
    6379,  // Redis - in-memory database, often unsecured
    27017, // MongoDB - NoSQL database, often default config
];

/// Fast compile-time check for commonly targeted ports
/// 
/// This const function allows efficient checking of whether a port
/// is in the "interesting" category without runtime array searches.
/// The compiler can optimize this into a simple comparison chain.
/// 
/// Usage in enhanced detection logic:
/// - Normal port scan: 10 random ports = 1.0x severity
/// - Interesting port scan: 10 interesting ports = 1.5x severity
/// - Mixed scan: Weight each port based on type
/// 
/// @param port: Port number to check (0-65535)
/// @return: true if port is commonly targeted by attackers
/// 
/// Performance: O(1) compile-time optimization, no runtime overhead
pub const fn is_interesting_port(port: u16) -> bool {
    // matches! macro generates efficient comparison chain
    // Compiler optimizes this into jump table or binary search tree
    matches!(port,
        21 | 22 | 23 | 25 | 53 | 80 | 110 | 135 | 139 | 143 |
        443 | 445 | 993 | 995 | 1433 | 3306 | 3389 | 5432 | 6379 | 27017
    )
}

//=============================================================================
// USAGE EXAMPLES AND INTEGRATION NOTES
//=============================================================================
//
// This common module enables several usage patterns:
//
// 1. Basic Detection:
//    if scan_info.unique_ports > PORT_SCAN_THRESHOLD {
//        // Trigger alert
//    }
//
// 2. Enhanced Detection with Port Weighting:
//    let mut score = 0.0;
//    for port in scanned_ports {
//        score += if is_interesting_port(port) { 1.5 } else { 1.0 };
//    }
//    if score > ENHANCED_THRESHOLD {
//        // Trigger weighted alert
//    }
//
// 3. Temporal Analysis:
//    let duration = scan_info.last_seen - scan_info.first_seen;
//    let velocity = scan_info.unique_ports as f64 / (duration as f64 / 1e9);
//    // ports per second
//
// 4. Pattern Classification:
//    let retry_ratio = scan_info.total_attempts as f64 / scan_info.unique_ports as f64;
//    match retry_ratio {
//        r if r < 1.2 => "Stealthy scan (single attempts)",
//        r if r < 3.0 => "Normal scan (some retries)",  
//        _ => "Aggressive scan (many retries)"
//    }
//