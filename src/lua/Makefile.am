AUTOMAKE_OPTIONS=foreign no-dependencies

noinst_LIBRARIES = liblua.a

x_includedir = $(pkgincludedir)/lua

x_include_HEADERS = \
lua.h \
lua_ref.h \
lua_iface.h \
lua_table.h \
lua_arg.h \
lua_stack.h \
lua_util.h

liblua_a_SOURCES = \
lua.cc \
lua.h \
lua_ref.cc \
lua_ref.h \
lua_iface.h \
lua_util.cc \
lua_util.h \
lua_table.h \
lua_arg.h \
lua_stack.h \
lua_stack_test.cc \
lua_test_common.h

AM_CXXFLAGS = @AM_CXXFLAGS@
