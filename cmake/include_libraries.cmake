
# required libraries
find_package(Threads REQUIRED)
find_package(DAQ REQUIRED)
find_package(DNET REQUIRED)
find_package(HWLOC REQUIRED)
find_package(LuaJIT REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(PCAP REQUIRED)
find_package(PCRE REQUIRED)
find_package(SFBPF REQUIRED)
find_package(ZLIB REQUIRED)

# optional libraries
find_package(LibLZMA QUIET)
find_package(Asciidoc QUIET)
find_package(DBLATEX QUIET)
find_package(Ruby QUIET 1.8.7)
find_package(HS QUIET)
find_package(SafeC QUIET)

