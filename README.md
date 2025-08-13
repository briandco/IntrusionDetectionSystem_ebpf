# eBPF Networking

A Rust-based eBPF networking project using the Aya framework for kernel-space and user-space networking applications.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Build Instructions](#build-instructions)
- [Running the Application](#running-the-application)
- [Cross-compiling](#cross-compiling)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Prerequisites

### Required Tools

1. **Rust Toolchains**:
   - Stable: `rustup toolchain install stable`
   - Nightly: `rustup toolchain install nightly --component rust-src`

2. **eBPF Dependencies**:
   - bpf-linker: `cargo install bpf-linker` (use `--no-default-features` on macOS)
   - For eBPF target: `rustup target add bpfel-unknown-none`

3. **Cross-compilation Dependencies** (if needed):
   - Target architecture: `rustup target add ${ARCH}-unknown-linux-musl`
   - LLVM: `brew install llvm` (macOS) or equivalent for your OS
   - C toolchain: [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (macOS)

### System Requirements

- Linux system with eBPF support (kernel version 4.1+)
- Root privileges for loading eBPF programs
- Network interface for testing

## Project Structure

```
ebpf-networking/
├── ebpf-networking-ebpf/    # Kernel-space eBPF code
├── src/                     # User-space Rust code
├── Cargo.toml              # User-space dependencies
├── README.md               # This file
└── LICENSE-*               # License files
```

## Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd ebpf-networking
   ```

2. **Install dependencies**:
   ```bash
   # Install Rust toolchains
   rustup toolchain install stable
   rustup toolchain install nightly --component rust-src
   
   # Add eBPF target
   rustup target add bpfel-unknown-none
   
   # Install bpf-linker
   cargo install bpf-linker
   ```

## Build Instructions

### Building eBPF Kernel Code

Navigate to the eBPF directory and build:

```bash
cd ebpf-networking-ebpf
cargo +nightly build --release --target=bpfel-unknown-none -Z build-std=core
```

### Building User-space Code

From the project root:

```bash
cargo build --release
```

### Complete Build Process

To build both components in one step, use the automated build script from the project root:

```bash
# Build both kernel and user-space components
cargo build --release
```

*Note: Cargo build scripts automatically handle the eBPF compilation and inclusion.*

## Running the Application

### Basic Usage

```bash
sudo RUST_LOG=info ./target/release/ebpf-networking --iface <interface_name>
```

### Example

```bash
sudo RUST_LOG=info ./target/release/ebpf-networking --iface enp0s3
```

### Alternative Run Command

You can also use cargo run with elevated privileges:

```bash
cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --iface enp0s3
```

### Environment Variables

- `RUST_LOG`: Set logging level (e.g., `debug`, `info`, `warn`, `error`)
- `INTERFACE`: Network interface name (can also be passed as `--iface` argument)
