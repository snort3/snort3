# creating pkg-config module.  these will all be substituted into snort.pc

# set pkgconfig vars

set(prefix "${CMAKE_INSTALL_PREFIX}")
set(exec_prefix "\${prefix}")
set(bindir "\${exec_prefix}/bin")
set(libdir "\${exec_prefix}/lib")
set(includedir "\${prefix}/include")
set(datarootdir "\${prefix}/share")
set(datadir "\${datarootdir}")
set(mandir "\${datarootdir}/man")
set(infodir "\${datarootdir}/info")

set(DAQ_CPPFLAGS "-I${DAQ_INCLUDE_DIR}")

# create & install pkgconfig file

configure_file(
    "${CMAKE_SOURCE_DIR}/snort.pc.in"
    "${CMAKE_BINARY_DIR}/snort.pc"
    @ONLY
)

install (FILES ${CMAKE_BINARY_DIR}/snort.pc
    DESTINATION "lib/pkgconfig/"
)
