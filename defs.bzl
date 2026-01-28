"""Shared build definitions for snort.

This file contains project-wide compiler options, include paths,
and other shared build configuration.
"""

# Global compiler flags (from CMake)
# Includes global include paths as -I flags
COPTS = [
    "-DHAVE_CONFIG_H",
    "-D_DEFAULT_SOURCE",
    "-D_BSD_SOURCE",
    "-D_POSIX_C_SOURCE=200809L",
    "-Isrc/network_inspectors",
    "-I.",
    "-I/usr/include/uuid",
    "-I/usr/local/include",

    "-I/usr/include/luajit-2.1",  # LuaJIT headers
    "-I/usr/include/hs",           # Hyperscan headers

    "-DHAVE_NUMA",
    # Work around header collision: src/main/numa.h shadows /usr/include/numa.h
    # Force system includes to be found first
    "-include", "/usr/include/numa.h",
    "-include", "/usr/include/numaif.h",
]

# Linker options for system libraries
# Auto-detected from source files and CMake dependencies
LINKOPTS = [
    "-L/usr/local/lib",
    "-lcrypto",
    "-llzma",
    "-lpcap",
    "-lssl",
    "-lunwind",
    "-luuid",
    "-lz",
    "-ldaq",
    "-ldnet",
    "-lhwloc",
    "-lluajit-5.1",  # Was: -lluajit (correct LuaJIT library name)
    "-lhs",          # Hyperscan library
    "-lnuma",        # NUMA library
    "-lpcre2-8",     # Was: -lpcre2 (correct PCRE2 library name)
]

# Standard visibility for all targets
DEFAULT_VISIBILITY = ["//visibility:public"]
