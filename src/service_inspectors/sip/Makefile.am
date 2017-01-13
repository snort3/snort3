
file_list = \
sip_common.h \
sip_config.h \
sip_config.cc \
sip_utils.h \
sip_utils.cc \
sip_parser.h \
sip_parser.cc \
sip_dialog.h \
sip_dialog.cc \
sip.cc \
sip.h \
sip_roptions.h \
sip_module.cc \
sip_module.h \
ips_sip.cc \
ips_sip_stat_code.cc \
ips_sip_method.cc

#if STATIC_INSPECTORS
noinst_LIBRARIES = libsip.a
libsip_a_SOURCES = $(file_list)
#else
#shlibdir = $(pkglibdir)/inspectors
#shlib_LTLIBRARIES = sip.la
#sip_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
#sip_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
#sip_la_SOURCES = $(file_list)
#endif

