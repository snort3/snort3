AUTOMAKE_OPTIONS=foreign no-dependencies

noinst_LIBRARIES = liblua.a

liblua_a_SOURCES = \
lua.cc \
lua.h \
lua_arg.h \
lua_iface.h \
lua_ref.cc \
lua_ref.h \
lua_stack.h \
lua_table.h \
lua_test_common.h \
lua_util.cc \
lua_util.h

if ENABLE_UNIT_TESTS
liblua_a_SOURCES += lua_stack_test.cc
endif

