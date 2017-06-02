
file_list = \
binder.cc \
binder.h \
binding.h \
bind_module.cc \
bind_module.h

#if STATIC_INSPECTORS
noinst_LIBRARIES = libbinder.a
libbinder_a_SOURCES = $(file_list)
#else
# need to fix undefineds first :(
#shlibdir = $(pkglibdir)/inspectors
#shlib_LTLIBRARIES = binder.la
#binder_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
#binder_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
#binder_la_SOURCES = $(file_list)
#endif

