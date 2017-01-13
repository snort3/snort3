
file_list = \
smtp_config.h \
smtp.cc \
smtp.h \
smtp_util.cc \
smtp_util.h \
smtp_xlink2state.cc \
smtp_xlink2state.h \
smtp_normalize.cc \
smtp_normalize.h \
smtp_paf.cc \
smtp_paf.h \
smtp_module.cc \
smtp_module.h

# can't be linked dynamically yet
#if STATIC_INSPECTORS
noinst_LIBRARIES = libsmtp.a
libsmtp_a_SOURCES = $(file_list)
#else
#shlibdir = $(pkglibdir)/inspectors
#shlib_LTLIBRARIES = smtp.la
#smtp_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
#smtp_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
#smtp_la_SOURCES = $(file_list)
#endif

