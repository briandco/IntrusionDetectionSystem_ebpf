//=============================================================================
// eBPF USERSPACE CONTROL APPLICATION
//=============================================================================
// This is the userspace component of the eBPF port scan detection system.
// It handles loading, attaching, and managing the eBPF program that runs
// in kernel space. This application serves as the "control plane" while
// the eBPF program serves as the "data plane" for network monitoring.

use aya::programs::{SchedClassifier, TcAttachType, tc};  // Traffic Control integration
use clap::Parser;                                        // Command-line argument parsing
#[rustfmt::skip]
use log::{debug, warn};                                  // Logging macros (skip rustfmt)
use tokio::signal;                                       // Async signal handling

//=============================================================================
// COMMAND-LINE INTERFACE DEFINITION
//=============================================================================

/// Command-line options for the eBPF port scan detector
/// 
/// Uses the `clap` crate for automatic argument parsing and help generation.
/// This provides a clean interface for configuring the monitoring system.
#[derive(Debug, Parser)]
struct Opt {
    /// Network interface to monitor for port scanning activity
    /// 
    /// Specifies which network interface the eBPF program should be attached to.
    /// The program will monitor all traffic passing through this interface.
    /// 
    /// Examples:
    /// - "eth0": Primary Ethernet interface (common on servers)
    /// - "wlan0": Wireless interface (common on laptops)  
    /// - "enp0s3": Predictable interface names (systemd naming)
    /// - "docker0": Docker bridge interface
    /// - "any": Special interface that captures all traffic (Linux-specific)
    /// 
    /// Default: "eth0" (most common server interface)
    /// Usage: --iface eth0 or -i wlan0
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

//=============================================================================
// MAIN APPLICATION ENTRY POINT
//=============================================================================

/// Main async function that orchestrates the eBPF program lifecycle
/// 
/// This function performs the complete setup, deployment, and cleanup cycle:
/// 1. Parses command-line arguments
/// 2. Configures system resources and permissions
/// 3. Loads eBPF program from embedded bytecode
/// 4. Attaches program to network interface  
/// 5. Monitors for shutdown signals
/// 6. Performs graceful cleanup on exit
/// 
/// The #[tokio::main] macro converts this async function into the program
/// entry point, setting up the async runtime automatically.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    //-------------------------------------------------------------------------
    // STEP 1: PARSE COMMAND-LINE ARGUMENTS
    //-------------------------------------------------------------------------
    
    // Parse command-line arguments using clap
    // This automatically handles --help, --version, and argument validation
    let opt = Opt::parse();
    
    // Initialize logging system
    // This enables log::debug!(), log::info!(), log::warn!(), log::error!() macros
    // Log level can be controlled via RUST_LOG environment variable
    // Examples: RUST_LOG=debug, RUST_LOG=info, RUST_LOG=warn
    env_logger::init();

    //-------------------------------------------------------------------------
    // STEP 2: CONFIGURE SYSTEM RESOURCES
    //-------------------------------------------------------------------------
    
    // Increase memory lock limit for eBPF program loading
    // 
    // eBPF programs and maps must be locked in physical memory (not swappable).
    // Older kernels use RLIMIT_MEMLOCK to limit this, while newer kernels
    // use cgroup-based memory accounting (more flexible).
    // 
    // Setting RLIM_INFINITY ensures we don't hit artificial limits during
    // program loading, especially for large programs or many maps.
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,  // Current (soft) limit: unlimited
        rlim_max: libc::RLIM_INFINITY,  // Maximum (hard) limit: unlimited
    };
    
    // Apply the memory limit using low-level libc call
    // This is necessary because Rust's std library doesn't expose rlimit
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        // Log failure but continue - modern kernels may not need this
        // Non-zero return indicates the syscall failed
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    //-------------------------------------------------------------------------
    // STEP 3: LOAD eBPF PROGRAM FROM EMBEDDED BYTECODE
    //-------------------------------------------------------------------------
    
    // Load eBPF program from bytecode embedded at compile-time
    // 
    // The include_bytes_aligned! macro embeds the compiled eBPF object file
    // directly into the userspace binary. This approach has several benefits:
    // - No separate files to distribute or manage
    // - Version synchronization between userspace and eBPF code
    // - Atomic deployments (single binary contains everything)
    // - No runtime file system dependencies
    // 
    // The concat! and env! macros build the path to the compiled eBPF object:
    // - env!("OUT_DIR"): Build output directory (target/debug/build/...)
    // - "/ebpf-networking": Name of the compiled eBPF object file
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ebpf-networking"
    )))?;
    
    // Alternative approaches for eBPF loading:
    // - Bpf::load_file("path/to/program.o"): Load from file system
    // - Bpf::load_bytes(bytes): Load from byte array at runtime
    // - Custom loaders for network/remote loading scenarios

    //-------------------------------------------------------------------------
    // STEP 4: INITIALIZE eBPF LOGGING BRIDGE
    //-------------------------------------------------------------------------
    
    // Set up logging bridge between eBPF and userspace
    // 
    // This enables eBPF programs to send log messages to userspace using
    // macros like warn!(), debug!(), etc. The logs appear in the userspace
    // application's log output, making debugging much easier.
    // 
    // The logging bridge works by:
    // 1. eBPF program calls bpf_trace_printk() or similar helpers
    // 2. EbpfLogger reads from /sys/kernel/debug/tracing/trace_pipe
    // 3. Messages are formatted and sent to userspace logger
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // Failure is non-fatal - program will work without logging
        // This can happen if eBPF program has no log statements
        warn!("failed to initialize eBPF logger: {e}");
    }

    //-------------------------------------------------------------------------  
    // STEP 5: EXTRACT NETWORK INTERFACE PARAMETER
    //-------------------------------------------------------------------------
    
    // Destructure parsed arguments to get interface name
    let Opt { iface } = opt;

    //-------------------------------------------------------------------------
    // STEP 6: CONFIGURE TRAFFIC CONTROL (TC) QDISC
    //-------------------------------------------------------------------------
    
    // Add clsact qdisc (queueing discipline) to the network interface
    // 
    // TC (Traffic Control) is Linux's framework for managing network traffic.
    // A qdisc controls how packets are queued and scheduled for transmission.
    // 
    // The "clsact" qdisc is special - it provides attachment points for
    // classifiers and actions on both ingress (incoming) and egress (outgoing)
    // traffic without actually changing packet scheduling behavior.
    // 
    // Why clsact is needed:
    // - Creates attachment points for eBPF TC programs
    // - Enables packet interception at network layer
    // - Works for both ingress and egress traffic
    // - Minimal performance impact (passthrough by default)
    let _ = tc::qdisc_add_clsact(&iface);
    
    // Note: Error is ignored with let _ because:
    // - Adding clsact when it already exists is harmless
    // - Manual cleanup: sudo tc qdisc del dev eth0 clsact
    // - Failure here is usually not fatal to program operation

    //-------------------------------------------------------------------------
    // STEP 7: LOCATE AND PREPARE eBPF PROGRAM
    //-------------------------------------------------------------------------
    
    // Find the eBPF program by name within the loaded object
    // 
    // eBPF object files can contain multiple programs. We need to locate
    // the specific program we want to use by its function name.
    // "ebpf_networking" corresponds to the #[classifier] function in the eBPF code.
    let program: &mut SchedClassifier = ebpf
        .program_mut("ebpf_networking")     // Find program by name
        .unwrap()                          // Panic if program not found (dev error)
        .try_into()?;                      // Convert to SchedClassifier type

    // The try_into() conversion ensures the program is the correct type:
    // - SchedClassifier: For TC (Traffic Control) attachment
    // - XdpProgram: For XDP (eXpress Data Path) attachment  
    // - SocketFilter: For socket-level filtering
    // - etc.

    //-------------------------------------------------------------------------
    // STEP 8: LOAD PROGRAM INTO KERNEL
    //-------------------------------------------------------------------------
    
    // Load the eBPF program into the kernel
    // 
    // This step involves several kernel operations:
    // 1. eBPF bytecode verification (safety and correctness)
    // 2. JIT compilation (convert bytecode to native machine code)
    // 3. Memory allocation for program and maps
    // 4. Permission and capability checks
    // 5. Program registration in kernel namespace
    program.load()?;
    
    // Verification can fail for many reasons:
    // - Invalid memory accesses or bounds violations
    // - Unreachable code or infinite loops
    // - Invalid BPF helper function calls
    // - Map access violations or type mismatches
    // - Stack usage exceeding limits
    // - Program size exceeding limits

    //-------------------------------------------------------------------------
    // STEP 9: ATTACH PROGRAM TO NETWORK INTERFACE  
    //-------------------------------------------------------------------------
    
    // Attach the loaded program to the specified network interface
    // 
    // This makes the program active - it will now process network packets.
    // TcAttachType::Ingress means the program runs on incoming packets.
    // 
    // Attachment options:
    // - TcAttachType::Ingress: Process incoming packets (before routing)
    // - TcAttachType::Egress: Process outgoing packets (after routing)  
    // 
    // For port scan detection, Ingress is typically preferred because:
    // - Scans are incoming connection attempts from external sources
    // - We want to detect attacks before they reach applications
    // - Ingress attachment has lower latency than egress
    program.attach(&iface, TcAttachType::Ingress)?;
    
    // At this point, the eBPF program is actively monitoring network traffic!
    // It will:
    // - Process every incoming packet on the interface
    // - Track connection attempts and port scanning patterns
    // - Send alerts through the perf event array
    // - Log suspicious activity

    //-------------------------------------------------------------------------
    // STEP 10: WAIT FOR SHUTDOWN SIGNAL
    //-------------------------------------------------------------------------
    
    // Set up graceful shutdown handling
    // 
    // Create a future that completes when Ctrl+C is pressed.
    // This allows the program to run indefinitely while remaining responsive
    // to shutdown requests from users or process managers.
    let ctrl_c = signal::ctrl_c();
    
    println!("Waiting for Ctrl-C...");
    println!("eBPF port scan detector is now active on interface: {}", iface);
    println!("Monitor logs for scan detection alerts.");
    
    // Await the Ctrl+C signal
    // This is the main "run loop" - the program stays here until interrupted
    // Meanwhile, the eBPF program continues processing packets in kernel space
    ctrl_c.await?;

    //-------------------------------------------------------------------------
    // STEP 11: GRACEFUL SHUTDOWN
    //-------------------------------------------------------------------------
    
    println!("Exiting...");
    
    // Graceful shutdown happens automatically when main() exits:
    // 1. Aya runtime automatically detaches eBPF program from interface
    // 2. Kernel automatically unloads program and frees resources
    // 3. All BPF maps are cleaned up and memory is released
    // 4. TC qdisc attachment points are cleaned (program detached)
    // 
    // Manual cleanup (if needed):
    // - sudo tc qdisc del dev eth0 clsact  # Remove qdisc entirely
    // - sudo tc filter del dev eth0 ingress # Remove just the filter
    
    Ok(())
}

//=============================================================================
// PROGRAM LIFECYCLE AND ARCHITECTURE
//=============================================================================
//
// This userspace application serves as the control plane for the eBPF-based
// network monitoring system. Here's how the components interact:
//
// ┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
// │   Userspace     │    │     Kernel       │    │   Hardware/     │
// │   Application   │    │     Space        │    │   Network       │
// └─────────────────┘    └──────────────────┘    └─────────────────┘
//          │                        │                        │
//          │ 1. Load eBPF program   │                        │
//          │─────────────────────→ │                        │
//          │                        │                        │
//          │ 2. Attach to interface │                        │
//          │─────────────────────→ │                        │
//          │                        │                        │
//          │                        │ 3. Process packets     │
//          │                        │←─────────────────────→│
//          │                        │                        │
//          │ 4. Receive alerts      │                        │
//          │←─────────────────────  │                        │
//          │                        │                        │
//          │ 5. Handle shutdown     │                        │
//          │─────────────────────→ │                        │
//
// Key responsibilities:
// - Userspace: Program management, configuration, alerting, logging
// - Kernel eBPF: High-speed packet processing, pattern detection
// - Hardware: Packet capture, interrupt generation
//
//=============================================================================
// DEPLOYMENT AND OPERATIONAL CONSIDERATIONS
//=============================================================================
//
// System Requirements:
// - Linux kernel 4.18+ (for TC + eBPF support)
// - CAP_BPF and CAP_SYS_ADMIN capabilities (or root access)
// - Network interface with traffic to monitor
// - Sufficient locked memory limits (handled automatically)
//
// Performance Characteristics:
// - Userspace CPU usage: Very low (just management overhead)
// - Kernel CPU usage: Low to moderate (depends on traffic volume)
// - Memory usage: ~1-2MB for maps and program (configurable)
// - Latency impact: Microseconds per packet (minimal)
//
// Monitoring and Observability:
// - eBPF program logs via trace_pipe (/sys/kernel/debug/tracing/)
// - Userspace logs via env_logger (RUST_LOG environment variable)
// - Perf events for real-time alerts (can be extended)
// - BPF map inspection via bpftool or custom tooling
//
// Security Considerations:
// - Runs with elevated privileges (required for eBPF)
// - Only monitors traffic (doesn't block or modify packets)
// - Memory-safe implementation (Rust + eBPF verifier)
// - Fail-open design (allows traffic if program fails)
//