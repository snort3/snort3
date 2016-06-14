
AM_CPPFLAGS+=-I$(top_srcdir)/src/network_inspectors/appid

file_list = \
common_util.h \
fw_avltree.cc \
fw_avltree.h \
ip_funcs.cc \
ip_funcs.h \
network_set.cc \
network_set.h \
output_file.cc \
output_file.h \
sfksearch.cc \
sfksearch.h \
sf_mlmp.cc \
sf_mlmp.h \
sf_multi_mpse.cc \
sf_multi_mpse.h \
sfutil.cc \
sfutil.h

noinst_LIBRARIES = libappid_util.a
libappid_util_a_SOURCES = $(file_list)

#  FIXIT - H Uncomment once tests are ready.
#if BUILD_UNIT_TESTS
#SUBDIRS = test
#endif