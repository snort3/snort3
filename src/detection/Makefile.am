AUTOMAKE_OPTIONS=foreign no-dependencies

noinst_LIBRARIES = libdetection.a

x_includedir = $(pkgincludedir)/detection

x_include_HEADERS = \
detection_defines.h \
rule_option_types.h \
rules.h \
signature.h \
treenodes.h

libdetection_a_SOURCES = \
detect.cc \
detect.h \
detection_options.cc \
detection_options.h \
detection_util.cc \
detection_util.h \
fpcreate.cc \
fpcreate.h \
fpdetect.cc \
fpdetect.h \
pcrm.cc \
pcrm.h \
sfrim.cc \
sfrim.h \
signature.cc \
treenodes.cc \
tag.cc \
tag.h

AM_CXXFLAGS = @AM_CXXFLAGS@

