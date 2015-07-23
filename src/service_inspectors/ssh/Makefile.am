
file_list = \
ssh_config.h \
ssh.cc \
ssh.h \
ssh_module.cc \
ssh_module.h

if STATIC_INSPECTORS
noinst_LIBRARIES = libssh.a
libssh_a_SOURCES = $(file_list)
else
shlibdir = $(pkglibdir)/inspectors
shlib_LTLIBRARIES = libssh.la
libssh_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libssh_la_LDFLAGS = -export-dynamic -shared
libssh_la_SOURCES = $(file_list)
endif

AM_CXXFLAGS = @AM_CXXFLAGS@

