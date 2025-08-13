//=============================================================================
// eBPF BUILD SCRIPT (build.rs)
//=============================================================================
// This is a Cargo build script that automatically compiles eBPF programs
// as part of the normal Rust build process. It runs before the main
// application is built and ensures eBPF bytecode is ready for loading.
//
// Build scripts in Rust:
// - Named build.rs and placed in project root
// - Run during `cargo build` before compiling main code
// - Can generate code, compile native dependencies, set environment variables
// - Output goes to target/ directory alongside other build artifacts

use anyhow::{Context as _, anyhow};  // Error handling with context
use aya_build::cargo_metadata;       // Cargo workspace introspection

/// Main build script entry point
/// 
/// This function orchestrates the eBPF compilation process:
/// 1. Discovers the eBPF package in the Cargo workspace
/// 2. Builds the eBPF program using the Aya build system
/// 3. Handles errors with descriptive context
/// 
/// The compiled eBPF bytecode will be embedded in the final binary
/// or made available for runtime loading by the userspace program.
/// 
/// @return: Result indicating success/failure of the build process
fn main() -> anyhow::Result<()> {
    //-------------------------------------------------------------------------
    // STEP 1: DISCOVER WORKSPACE METADATA
    //-------------------------------------------------------------------------
    
    // Query Cargo for information about the current workspace
    // This gives us details about all packages, dependencies, and structure
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()  // Don't include dependency information (faster, we only need our packages)
        .exec()     // Execute the metadata query
        .context("MetadataCommand::exec")?;  // Add context to any errors
    
    // The cargo_metadata crate provides structured access to:
    // - Package names, versions, and paths
    // - Dependency relationships  
    // - Build targets and configurations
    // - Workspace structure and members
    
    //-------------------------------------------------------------------------
    // STEP 2: LOCATE THE eBPF PACKAGE
    //-------------------------------------------------------------------------
    
    // Search through all packages in the workspace to find our eBPF program
    // In typical Aya projects, the workspace contains:
    // - Main userspace application package (e.g., "ebpf-networking")
    // - eBPF kernel program package (e.g., "ebpf-networking-ebpf") 
    // - Common shared code package (e.g., "ebpf-networking-common")
    let ebpf_package = packages
        .into_iter()  // Convert package vector to iterator
        .find(|cargo_metadata::Package { name, .. }| {
            // Search for package with exact name "ebpf-networking-ebpf"
            // This naming convention is standard in Aya projects:
            // - Base name: "ebpf-networking" 
            // - eBPF suffix: "-ebpf" indicates kernel-space code
            // - Common suffix: "-common" indicates shared definitions
            name == "ebpf-networking-ebpf"
        })
        .ok_or_else(|| {
            // If package not found, create descriptive error
            // This helps developers debug workspace configuration issues
            anyhow!("ebpf-networking-ebpf package not found")
        })?;
    
    // Package discovery can fail if:
    // - Package name doesn't match exactly
    // - Package is not a workspace member
    // - Cargo.toml configuration errors
    // - Package is in different directory structure
    
    //-------------------------------------------------------------------------
    // STEP 3: BUILD THE eBPF PROGRAM
    //-------------------------------------------------------------------------
    
    // Use Aya's build system to compile the eBPF program
    // This performs several complex operations:
    // 1. Compiles Rust code to eBPF bytecode using special target
    // 2. Runs LLVM optimization passes for size and performance  
    // 3. Validates bytecode meets eBPF verifier requirements
    // 4. Generates object files that can be loaded by userspace
    aya_build::build_ebpf([ebpf_package])
    
    // The build_ebpf function:
    // - Takes an array/iterator of packages to build
    // - Handles cross-compilation to BPF target architecture  
    // - Manages LLVM toolchain integration
    // - Produces .o files containing eBPF bytecode
    // - Reports compilation errors with source context
    
    // Build output typically goes to:
    // target/bpfel-unknown-none/debug/ebpf-networking-ebpf
    // or
    // target/bpfel-unknown-none/release/ebpf-networking-ebpf
    
    // The compiled eBPF program can then be:
    // - Loaded directly by userspace applications
    // - Embedded as bytes in the final binary
    // - Distributed separately for runtime loading
}

//=============================================================================
// BUILD PROCESS OVERVIEW
//=============================================================================
//
// This build script is part of a multi-step compilation process:
//
// 1. Cargo runs build.rs (this script) first
//    ↓
// 2. build.rs compiles eBPF Rust code → eBPF bytecode
//    ↓  
// 3. Cargo compiles userspace Rust code → native binary
//    ↓
// 4. Final binary can load and run eBPF programs
//
// Dependencies and requirements:
// - LLVM toolchain with BPF backend
// - Aya build tools and runtime libraries
// - Linux kernel with eBPF support (for runtime)
// - Appropriate capabilities (CAP_BPF, CAP_SYS_ADMIN)
//
// Build targets:
// - eBPF: bpfel-unknown-none (little-endian) or bpfeb-unknown-none (big-endian)
// - Userspace: Standard Rust targets (x86_64-unknown-linux-gnu, etc.)
//
//=============================================================================
// WORKSPACE STRUCTURE EXAMPLE
//=============================================================================
//
// Typical Aya project workspace layout:
//
// ebpf-networking/                    ← Root workspace
// ├── Cargo.toml                     ← Workspace configuration
// ├── build.rs                       ← This build script
// ├── src/                           ← Userspace application code
// │   └── main.rs
// ├── ebpf-networking-ebpf/          ← eBPF kernel program
// │   ├── Cargo.toml
// │   └── src/
// │       └── main.rs
// └── ebpf-networking-common/        ← Shared data structures
//     ├── Cargo.toml
//     └── src/
//         └── lib.rs
//
// Cargo.toml workspace configuration:
// [workspace]
// members = [
//     "ebpf-networking-ebpf",
//     "ebpf-networking-common"  
// ]
//
//=============================================================================
// ERROR HANDLING AND DEBUGGING
//=============================================================================
//
// Common build failures and solutions:
//
// 1. "ebpf-networking-ebpf package not found"
//    → Check package name in Cargo.toml matches exactly
//    → Ensure package is in workspace members
//    → Verify directory structure
//
// 2. LLVM/BPF compilation errors
//    → Install LLVM with BPF backend support
//    → Check rustc BPF target: rustup target add bpfel-unknown-none
//    → Verify eBPF code follows kernel restrictions
//
// 3. "MetadataCommand::exec" errors  
//    → Check Cargo.toml syntax and validity
//    → Ensure cargo metadata command works manually
//    → Verify workspace configuration
//
// 4. Build script permissions/environment
//    → Ensure build environment has necessary tools
//    → Check file system permissions
//    → Verify network access if dependencies needed
//