
x_includedir = $(pkgincludedir)/main

noinst_LIBRARIES = libmain.a

x_include_HEADERS = \
policy.h \
snort_config.h \
snort_debug.h \
snort_types.h \
thread.h

libmain_a_SOURCES = \
analyzer.cc \
analyzer.h \
build.h \
help.cc \
help.h \
modules.cc \
modules.h \
policy.cc \
shell.cc \
shell.h \
snort.cc \
snort.h \
snort_config.cc \
snort_config.h

if DEBUG_MSGS
libmain_a_SOURCES += snort_debug.cc
endif

libmain_a_SOURCES += \
snort_module.cc \
snort_module.h \
thread.cc
