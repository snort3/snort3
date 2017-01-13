
file_list = \
rpc_decode.cc \
rpc_module.cc \
rpc_module.h

if STATIC_INSPECTORS
noinst_LIBRARIES = librpc_decode.a
librpc_decode_a_SOURCES = $(file_list)
else
shlibdir = $(pkglibdir)/inspectors
shlib_LTLIBRARIES = rpc_decode.la
rpc_decode_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
rpc_decode_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
rpc_decode_la_SOURCES = $(file_list)
endif

