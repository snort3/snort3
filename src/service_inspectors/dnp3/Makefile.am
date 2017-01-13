
file_list = \
dnp3.cc \
dnp3.h \
dnp3_map.cc \
dnp3_map.h \
dnp3_module.cc \
dnp3_module.h \
dnp3_reassembly.cc \
dnp3_reassembly.h \
dnp3_paf.cc\
dnp3_paf.h \
ips_dnp3_data.cc \
ips_dnp3_func.cc \
ips_dnp3_ind.cc \
ips_dnp3_obj.cc


if STATIC_INSPECTORS
noinst_LIBRARIES = libdnp3.a
libdnp3_a_SOURCES = $(file_list)
else
shlibdir = $(pkglibdir)/inspectors
shlib_LTLIBRARIES = dnp3.la
dnp3_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
dnp3_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
dnp3_la_SOURCES = $(file_list)
endif
