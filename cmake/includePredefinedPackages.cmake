
# required libraries
find_package(BISON REQUIRED)
find_package(FLEX REQUIRED)
find_package(ZLIB REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
find_package(LuaJIT REQUIRED)
find_package(DAQ REQUIRED)
find_package(PCAP REQUIRED)
find_package(PCRE REQUIRED)
find_package(DNET REQUIRED)

# optional libraries
find_package(Asciidoc QUIET)
find_package(DBLATEX QUIET)
find_package(Ruby QUIET 1.8.7)
