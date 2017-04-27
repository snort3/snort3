
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
analyzer_command.cc \
analyzer_command.h \
build.h \
help.cc \
help.h \
modules.cc \
modules.h \
policy.cc \
request.cc \
request.h \
shell.cc \
shell.h \
snort.cc \
snort.h \
snort_config.cc \
snort_config.h \
snort_module.cc \
snort_module.h \
swapper.cc \
swapper.h \
thread.cc \
thread_config.h \
thread_config.cc

if DEBUG_MSGS
libmain_a_SOURCES += snort_debug.cc
endif

if ENABLE_SHELL
libmain_a_SOURCES += \
control.cc \
control.h \
control_mgmt.cc \
control_mgmt.h
endif
