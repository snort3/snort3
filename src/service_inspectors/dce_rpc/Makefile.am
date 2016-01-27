file_list = \
dce2_co.h \
dce2_common.cc \
dce2_common.h \
dce2_list.cc \
dce2_list.h \
dce2_smb.cc \
dce2_smb.h \
dce2_smb_module.cc \
dce2_smb_module.h \
dce2_tcp.cc\
dce2_tcp.h \
dce2_tcp_module.cc \
dce2_tcp_module.h \
dce2_utils.cc \
dce2_utils.h \
ips_dce2_iface.cc \
ips_dce2_opnum.cc \
ips_dce2_stub_data.cc


if STATIC_INSPECTORS
noinst_LIBRARIES = libdce_rpc.a
libdce_rpc_a_SOURCES = $(file_list)
else
shlibdir = $(pkglibdir)/inspectors
shlib_LTLIBRARIES = libdce_rpc.la
libdce_rpc_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libdce_rpc_la_LDFLAGS = -export-dynamic -shared
libdce_rpc_la_SOURCES = $(file_list)
endif

AM_CXXFLAGS = @AM_CXXFLAGS@
