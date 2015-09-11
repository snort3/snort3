
bin_PROGRAMS = snort2lua

snort2lua_SOURCES = \
conversion_state.h \
conversion_defines.h \
init_state.h \
snort2lua.cc \
init_state.cc

snort2lua_LDADD = \
keyword_states/libkeyword_states.a \
preprocessor_states/libpreprocessor_states.a \
output_states/liboutput_states.a \
config_states/libconfig_states.a \
rule_states/librule_states.a \
helpers/libsnort2lua_helpers.a \
data/libdata.a \
data/data_types/libdata_types.a

SUBDIRS = \
helpers \
data \
keyword_states \
preprocessor_states \
output_states \
config_states \
rule_states

AM_CPPFLAGS = @snort2lua_CPPFLAGS@

