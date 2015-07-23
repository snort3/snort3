
file_list = \
binder.cc \
binding.h \
bind_module.cc \
bind_module.h

#if STATIC_INSPECTORS
noinst_LIBRARIES = libbinder.a
libbinder_a_SOURCES = $(file_list)
#else
# need to fix undefineds first :(
#shlibdir = $(pkglibdir)/inspectors
#shlib_LTLIBRARIES = libbinder.la
#libbinder_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
#libbinder_la_LDFLAGS = -export-dynamic -shared
#libbinder_la_SOURCES = $(file_list)
#endif

AM_CXXFLAGS = @AM_CXXFLAGS@

