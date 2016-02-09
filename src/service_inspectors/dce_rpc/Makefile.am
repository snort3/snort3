file_list = \
dce_co.h \
dce_common.cc \
dce_common.h \
dce_list.cc \
dce_list.h \
dce_smb.cc \
dce_smb.h \
dce_smb_module.cc \
dce_smb_module.h \
dce_smb_paf.cc \
dce_smb_paf.h \
dce_tcp.cc\
dce_tcp.h \
dce_tcp_module.cc \
dce_tcp_module.h \
dce_tcp_paf.cc \
dce_tcp_paf.h \
dce_utils.cc \
dce_utils.h \
ips_dce_iface.cc \
ips_dce_opnum.cc \
ips_dce_stub_data.cc


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
