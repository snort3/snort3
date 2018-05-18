# Snort++

The Snort++ project has been hard at work for a while now and we have
released the fourth alpha of the next generation Snort IPS (Intrusion
Prevention System).  This file will show you what Snort++ has to offer and
guide you through the steps from download to demo.  If you are unfamiliar
with Snort you should take a look at the Snort documentation first. We will
cover the following topics:

---

* [Overview](#overview)
* [Dependencies](#dependencies)
* [Download](#download)
* [Build Snort](#build-snort)
* [Run Snort](#run-snort)
* [Documentation](#documentation)
* [Squeal](#squeal)

# OVERVIEW

This version of Snort++ includes new features as well as all Snort 2.X
features and bug fixes for the base version of Snort except as indicated
below:

    Project = Snort++
    Binary = snort
    Version = 3.0.0-a4 build 235
    Base = 2.9.8 build 383

Here are some key features of Snort++:

* Support multiple packet processing threads
* Use a shared configuration and attribute table
* Use a simple, scriptable configuration
* Make key components pluggable
* Autodetect services for portless configuration
* Support sticky buffers in rules
* Autogenerate reference documentation
* Provide better cross platform support
* Facilitate component testing

Additional features on the roadmap include:

* Use a shared network map
* Support pipelining of packet processing
* Support hardware offload and data plane integration
* Support proxy mode
* Windows support

# DEPENDENCIES

If you already build Snort, you may have everything you need.  If not, grab
the latest:

* autotools or cmake to build from source
* daq from http://www.snort.org for packet IO
* dnet from https://github.com/dugsong/libdnet.git for network utility functions
* g++ >= 4.8 or other C++11 compiler
* hwloc from https://www.open-mpi.org/projects/hwloc/ for CPU affinity management
* LuaJIT from http://luajit.org for configuration and scripting
* OpenSSL from https://www.openssl.org/source/ for SHA and MD5 file signatures,
  the protected_content rule option, and SSL service detection
* pcap from http://www.tcpdump.org for tcpdump style logging
* pcre from http://www.pcre.org for regular expression pattern matching
* pkgconfig from https://www.freedesktop.org/wiki/Software/pkg-config/ to locate build dependencies
* zlib from http://www.zlib.net for decompression

Additional packages provide optional features.  Check the manual for more.

# DOWNLOAD

There is a source tarball available in the Downloads section on snort.org:

    snort-3.0.0-a3.tar.gz

You can also get the code with:

    git clone git://github.com/snortadmin/snort3.git

There are separate extras packages for cmake that provide additional
features and demonstrate how to build plugins. The source for extras
is in snort3_extra.git repo.

# BUILD SNORT

Follow these steps:

1.  Set up source directory:

  * If you are using a github clone:

    ```shell 
    cd snort3/
    ```

  * Otherwise, do this:

    ```shell
    tar zxf snort-tarball
    cd snort-3.0.0*
    ```
    
2.  Setup install path:

    ```shell
    export my_path=/path/to/snorty
    ```

3.  Compile and install:

  * To build with cmake and make, run configure_cmake.sh.  It will automatically create and populate a new subdirectory named 'build'.

    ```shell
    ./configure_cmake.sh --prefix=$my_path
    cd build
    make -j $(nproc) install
    ```

**_Note_**:

  * If you can do src/snort -V you built successfully.
  * If you are familiar with cmake, you can run cmake/ccmake instead of configure_cmake.sh.
  * cmake --help will list any available generators, such as Xcode.  Feel free to use one, however help with those will be provided separately.

# RUN SNORT

First set up the environment:

```shell
export LUA_PATH=$my_path/include/snort/lua/\?.lua\;\;
export SNORT_LUA_PATH=$my_path/etc/snort
```

Then give it a go:

* Snort++ provides lots of help from the command line.  Here are some examples:

    ```shell
    $my_path/bin/snort --help
    $my_path/bin/snort --help-module suppress
    $my_path/bin/snort --help-config | grep thread
    ```

* Examine and dump a pcap.  In the following, replace a.pcap with your
  favorite:

    ```shell
    $my_path/bin/snort -r a.pcap
    $my_path/bin/snort -L dump -d -e -q -r a.pcap
    ```

* Verify a config, with or w/o rules:

    ```shell
    $my_path/bin/snort -c $my_path/etc/snort/snort.lua
    $my_path/bin/snort -c $my_path/etc/snort/snort.lua -R $my_path/etc/snort/sample.rules
    ```

* Run IDS mode.  In the following, replace pcaps/ with a path to a directory
  with one or more *.pcap files:

    ```shell
    $my_path/bin/snort -c $my_path/etc/snort/snort.lua -R $my_path/etc/snort/sample.rules \
        -r a.pcap -A alert_test -n 100000
    ```

* Let's suppress 1:2123.  We could edit the conf or just do this:

    ```shell
    $my_path/bin/snort -c $my_path/etc/snort/snort.lua -R $my_path/etc/snort/sample.rules \
        -r a.pcap -A alert_test -n 100000 --lua "suppress = { { gid = 1, sid = 2123 } }"
    ```

* Go whole hog on a directory with multiple packet threads:

    ```shell
    $my_path/bin/snort -c $my_path/etc/snort/snort.lua -R $my_path/etc/snort/sample.rules \
        --pcap-filter \*.pcap --pcap-dir pcaps/ -A alert_fast --max-packet-threads 8
    ```

Additional examples are given in doc/usage.txt.

# DOCUMENTATION

Take a look at the manual, parts of which are generated by the code so it
stays up to date:

```shell
$my_path/share/doc/snort/snort_manual.pdf
$my_path/share/doc/snort/snort_manual.html
$my_path/share/doc/snort/snort_manual/index.html
```

It does not yet have much on the how and why, but it does have all the
currently available configuration, etc.  Some key changes to rules:

* you must use comma separated content sub options like this:  content:"foo", nocase;
* buffer selectors must appear before the content and remain in effect until changed
* pcre buffer selectors were deleted
* check the manual for more on Snort++ vs Snort
* check the manual reference section to understand how parameters are defined, etc.

It also covers new features not demonstrated here:

* snort2lua, a tool to convert Snort 2.X conf and rules to the new form
* a new HTTP inspector
* a binder, for mapping configuration to traffic
* a wizard for port-independent configuration
* improved rule parsing - arbitrary whitespace, C style comments, #begin/#end comments
* local and remote command line shell

# SQUEAL 
`o")~`

We hope you are as excited about Snort++ as we are.  Although a lot of work
remains, we wanted to give you a chance to try it out and let us know what
you think on the snort-users list.  In the meantime, we'll keep our snout
to the grindstone.

