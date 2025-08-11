#![no_std]

/// Time window for port scan detection (60 seconds)
/// This creates "buckets" - all activity within 60 seconds is grouped together
pub const SCAN_WINDOW_SECONDS:u64 = 60;

/// Threshold for port scan detection
/// If a single IP hits more than 10 unique ports in 60 seconds = SCAN!
pub const PORT_SCAN_THRESHOLD:u32 = 10;

/// Maximum entries in our BPF hash maps
/// Prevents memory exhaustion - older entries automatically evicted
pub const MAX_SCAN_ENTRIES: u32 = 10000;

//=============================================================================
// BPF MAP KEY STRUCTURES
//=============================================================================

/// Key for tracking scan attempts per source IP per time window
#[repr(C)] // C representation ensures consistent memory layout
#[derive(Clone, Copy)]
pub struct ScanKey{
    pub src_ip: u32,
    pub time_bucket: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ScanKey {}

//=============================================================================
// BPF MAP VALUE STRUCTURES  
//=============================================================================


/// Information tracked about each potential scanner
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ScanInfo{
    /// Number of unique destination ports this IP has tried
    pub unique_ports: u32,
    /// Total connection attempts (can be > unique_ports if retries)
    pub total_attempts: u32,
    /// When we first saw this IP in this time window
    pub first_seen: u64,
    /// When we last saw activity from this IP
    pub last_seen:u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ScanInfo {}

//=============================================================================
// ALERT STRUCTURE (eBPF → Userspace Communication)
//=============================================================================

/// Alert sent from eBPF to userspace when scan is detected
/// This travels through a perf event array
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ScanAlert {
    /// IP address of the scanner
    pub src_ip: u32,
    /// How many unique ports were scanned
    pub unique_ports: u32,
    /// Total scan attempts
    pub total_attempts: u32,
    /// Which time bucket this occurred in
    pub time_window: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ScanAlert {}

// #[repr(C)]
// #[derive(Clone, Copy)]
// pub struct PortKey {
//     pub src_ip: u32,
//     pub time_bucket: u32,  // Truncated to u32 - still gives us plenty of time range
//     pub dest_port: u16,
//     pub _padding: u16,     // Explicit padding ensures proper alignment
// }

//=============================================================================
// HELPER CONSTANTS (Optional - for better detection)
//=============================================================================

/// Well-known service ports that are commonly targeted
/// Scanning these is more suspicious than random high ports
pub const INTERESTING_PORTS: &[u16] = &[
    21,   // FTP
    22,   // SSH  
    23,   // Telnet
    25,   // SMTP
    53,   // DNS
    80,   // HTTP
    110,  // POP3
    135,  // RPC
    139,  // NetBIOS
    143,  // IMAP
    443,  // HTTPS
    445,  // SMB
    993,  // IMAPS
    995,  // POP3S
    1433, // SQL Server
    3306, // MySQL
    3389, // RDP
    5432, // PostgreSQL
    6379, // Redis
    27017, // MongoDB
];

/// Check if a port is commonly targeted by scanners
pub const fn is_interesting_port(port: u16) -> bool {
    // Simple compile-time check for common ports
    matches!(port, 
        21 | 22 | 23 | 25 | 53 | 80 | 110 | 135 | 139 | 143 |
        443 | 445 | 993 | 995 | 1433 | 3306 | 3389 | 5432 | 6379 | 27017
    )
}
