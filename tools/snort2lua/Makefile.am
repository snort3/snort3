AUTOMAKE_OPTIONS=foreign  no-dependencies

bin_PROGRAMS = snort2lua

snort2lua_SOURCES = \
conversion_state.h \
option_parser.h \
init_state.h \
snort2lua.cc \
init_state.cc

snort2lua_LDADD = \
utils/libsnort2lua_utils.a \
data/libdata.a \
keyword_states/libkeyword_states.a \
preprocessor_states/libpreprocessor_states.a \
output_states/liboutput_states.a \
config_states/libconfig_states.a \
rule_states/librule_states.a

snort2lua_CFLAGS = @CFLAGS@ $(AM_CFLAGS)

SUBDIRS = \
utils \
data \
keyword_states \
preprocessor_states \
output_states \
config_states \
rule_states

AM_CXXFLAGS = @AM_CXXFLAGS@

