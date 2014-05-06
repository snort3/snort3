AUTOMAKE_OPTIONS=foreign no-dependencies

file_list = \
nhttp_inspect.cc nhttp_inspect.h \
nhttp_msgheader.cc nhttp_msgheader.h \
nhttp_headnorm.cc nhttp_headnorm.h \
nhttp_strtocode.cc nhttp_strtocode.h \
nhttp_api.cc nhttp_api.h \
nhttp_tables.cc \
nhttp_module.cc nhttp_module.h \
nhttp_testinput.cc nhttp_testinput.h \
nhttp_flowdata.cc nhttp_flowdata.h \
nhttp_scratchpad.h nhttp_enum.h


#if STATIC_INSPECTORS
noinst_LIBRARIES = libnhttp_inspect.a
libnhttp_inspect_a_SOURCES = $(file_list)
#else
# need to fix undefineds first :(
#shlibdir = $(pkglibdir)/inspectors
#shlib_LTLIBRARIES = libnhttp_inspect.la
#libnhttp_inspect_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
#libnhttp_inspect_la_LDFLAGS = -export-dynamic -shared
#libnhttp_inspect_la_SOURCES = $(file_list)
#endif

AM_CXXFLAGS = @AM_CXXFLAGS@

