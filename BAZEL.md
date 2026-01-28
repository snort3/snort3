# Bazel Build System for Snort3

This document describes the Bazel build configuration for Snort3, including build settings, toolchain configuration, and platform support.

## Overview

Snort3 has been migrated to use Bazel as an alternative build system alongside the existing CMake build. This Bazel configuration supports:

- **Modern bzlmod** (MODULE.bazel) - Bazel 7.0+ required
- **Platform support** - Linux x86_64
- **C++17 standard** - Matches CMake configuration
- **Incremental builds** - Fast rebuilds with intelligent caching

> **Note:** Bazel 9+ no longer supports the legacy WORKSPACE file. This project uses MODULE.bazel exclusively.

---

## Files Overview

### Core Bazel Files

| File | Purpose |
|------|---------|
| `MODULE.bazel` | Module definition with external dependencies (bzlmod) |
| `BUILD.bazel` | Root build file with main targets |
| `defs.bzl` | Shared compiler flags (COPTS) and linker flags (LINKOPTS) |
| `.bazelrc` | Bazel configuration and build settings |

### Generated BUILD Files

```
snort3/
├── MODULE.bazel              # Bzlmod module definition
├── BUILD.bazel               # Root build targets
├── defs.bzl                  # Compiler/linker flags
├── .bazelrc                  # Bazel settings
├── src/
│   ├── BUILD.bazel          # Main snort binary and libraries
│   ├── codecs/BUILD.bazel   # Codec plugins
│   ├── inspectors/BUILD.bazel
│   └── ... (200+ BUILD files)
└── tools/
    ├── u2boat/BUILD.bazel   # Utility tools
    ├── u2spewfoo/BUILD.bazel
    └── snort2lua/BUILD.bazel
```

---

## .bazelrc - Build Configuration

The `.bazelrc` file configures Bazel's build behavior:

```ini
# Build settings
build --cxxopt=-std=c++17     # C++17 standard (matches CMake)
build --copt=-fPIC            # Position-independent code
build --cxxopt=-fPIC

# Test settings
test --test_output=errors     # Show only failed test output

# Output
build --color=yes             # Colored output
build --show_timestamps       # Show build timing
```

### Key Settings

- **C++17 Standard**: Ensures compatibility with modern C++ features used in Snort3
- **Position-Independent Code (PIC)**: Required for shared library builds
- **Test Output**: Only shows errors to reduce noise during test runs
- **Timestamps**: Helps identify slow build steps

### Custom Build Configurations

You can override settings via command line:

```bash
# Debug build with symbols
bazel build //src:snort -c dbg

# Optimized release build
bazel build //src:snort -c opt

# Verbose build output
bazel build //src:snort --subcommands

# Parallel build with specific job count
bazel build //src:snort --jobs=8
```

---

## MODULE.bazel - Dependency Management

Snort3 uses **bzlmod** (MODULE.bazel) instead of the legacy WORKSPACE file.

> **Important:** Bazel 9.0+ has removed WORKSPACE support. MODULE.bazel is now the only way to manage dependencies.

### Module Definition

```python
module(
    name = "snort",
    version = "3.10.1.0",
)

# Core Bazel dependencies
bazel_dep(name = "platforms", version = "0.0.10")  # Platform detection
bazel_dep(name = "rules_cc", version = "0.0.9")    # C/C++ rules
```

### External Dependencies

Snort3 requires these system libraries (installed via package manager):

| Library | Purpose | Package Name (Ubuntu/Debian) |
|---------|---------|------------------------------|
| **DAQ** | Data AcQuisition library | `libdaq-dev` |
| **libdnet** | Network utility library | `libdumbnet-dev` |
| **LuaJIT** | Scripting engine | `libluajit-5.1-dev` |
| **OpenSSL** | Cryptography | `libssl-dev` |
| **PCAP** | Packet capture | `libpcap-dev` |
| **PCRE2** | Regex engine | `libpcre2-dev` |
| **Hyperscan** | Pattern matching | `libhyperscan-dev` |
| **hwloc** | Hardware locality | `libhwloc-dev` |
| **zlib** | Compression | `zlib1g-dev` |

**Note:** System libraries are linked via `-l` flags in `defs.bzl` rather than bzlmod dependencies.

---

## Toolchain Configuration

### Default Toolchain

Bazel automatically uses the system's default C/C++ toolchain (typically GCC or Clang).

### Compiler Flags

Defined in `defs.bzl`:

```python
COPTS = [
    "-std=c++17",                      # C++17 standard
    "-fPIC",                          # Position-independent code
    "-I/usr/include/luajit-2.1",      # LuaJIT headers
    "-I/usr/include/hs",              # Hyperscan headers
    "-DHAVE_NUMA",                    # NUMA support
    "-include", "/usr/include/numa.h", # Header collision workaround
]

LINKOPTS = [
    "-lpthread",                      # Threading
    "-ldl",                          # Dynamic loading
    "-lluajit-5.1",                  # LuaJIT
    "-lhs",                          # Hyperscan
    "-lnuma",                        # NUMA
    "-lpcre2-8",                     # PCRE2
    "-lpcap",                        # Packet capture
    "-lssl", "-lcrypto",             # OpenSSL
    "-lz",                           # Zlib
]
```

---

## BUILD.bazel Structure

### Root BUILD.bazel

The root BUILD file exports common headers and defines shared configuration:

```python
# Export config.h for all packages
cc_library(
    name = "config_h",
    hdrs = ["config.h"],
    visibility = ["//visibility:public"],
)

# Export base headers
exports_files(glob(["*.h"]))
```

### Source BUILD Files

Each source directory has a BUILD.bazel with:

```python
# Example: src/codecs/BUILD.bazel
cc_library(
    name = "codecs",
    srcs = glob(["*.cc"]),
    hdrs = glob(["*.h"]),
    deps = [
        "//:config_h",
        "//src/framework:framework",
        "//src/protocols:protocols",
    ],
    copts = COPTS,
    visibility = ["//visibility:public"],
)
```

### Main Binary

The main Snort binary is defined in `src/BUILD.bazel`:

```python
cc_binary(
    name = "snort",
    srcs = ["main.cc"],
    deps = [
        ":main_lib",
        "//src/codecs:codecs",
        "//src/inspectors:inspectors",
        # ... 50+ library dependencies
    ],
    copts = COPTS,
    linkopts = LINKOPTS,
)
```

---

## Building with Bazel

### Prerequisites

1. **Install Bazel 7.0+**
   ```bash
   # Ubuntu/Debian
   sudo apt install apt-transport-https curl gnupg
   curl -fsSL https://bazel.build/bazel-release.pub.gpg | gpg --dearmor > bazel.gpg
   sudo mv bazel.gpg /etc/apt/trusted.gpg.d/
   echo "deb [arch=amd64] https://storage.googleapis.com/bazel-apt stable jdk1.8" | sudo tee /etc/apt/sources.list.d/bazel.list
   sudo apt update && sudo apt install bazel
   
   # Verify version
   bazel --version  # Should be 7.0 or higher
   ```

2. **Install system dependencies**
   ```bash
   sudo apt-get install -y \
       libdaq-dev libdumbnet-dev libluajit-5.1-dev \
       libssl-dev libpcap-dev libpcre2-dev libhyperscan-dev \
       libhwloc-dev zlib1g-dev flex bison
   ```

3. **Configure CMake (required for config.h)**
   ```bash
   export my_path=$HOME/snort_install
   ./configure_cmake.sh --prefix=$my_path
   ```

### Build Commands

```bash
# Build main snort binary
bazel build //src:snort

# Build specific tool
bazel build //tools/snort2lua:snort2lua

# Build all tools
bazel build //tools/u2boat:u2boat //tools/u2spewfoo:u2spewfoo //tools/snort2lua:snort2lua

# Build with optimization
bazel build //src:snort -c opt

# Build with debug symbols
bazel build //src:snort -c dbg

# Clean build
bazel clean --expunge
bazel build //src:snort
```

### Running Snort

```bash
# Run directly from Bazel
bazel run //src:snort -- --version

# Or use the built binary
./bazel-bin/src/snort --version
```