
AM_CPPFLAGS+=-I$(top_srcdir)/src/network_inspectors/appid

file_list = \
client_app_aim.cc \
client_app_aim.h \
client_app_api.h \
client_app_base.cc \
client_app_base.h \
client_app_bit.cc \
client_app_bit_tracker.cc \
client_app_config.h \
client_app_msn.cc \
client_app_msn.h \
client_app_rtp.cc \
client_app_smtp.cc \
client_app_smtp.h \
client_app_ssh.cc \
client_app_timbuktu.cc \
client_app_tns.cc \
client_app_vnc.cc \
client_app_ym.cc \
client_app_ym.h

noinst_LIBRARIES = libappid_client_plugins.a
libappid_client_plugins_a_SOURCES = $(file_list)

#  Uncomment once tests are ready.
#if BUILD_UNIT_TESTS
#SUBDIRS = test
#endif


