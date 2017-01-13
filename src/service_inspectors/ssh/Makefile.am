
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
shlib_LTLIBRARIES = ssh.la
ssh_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
ssh_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
ssh_la_SOURCES = $(file_list)
endif

