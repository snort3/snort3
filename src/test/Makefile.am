
noinst_LIBRARIES = libtest.a

BUILT_SOURCES = \
suite_decl.h \
suite_list.h

libtest_a_SOURCES = \
lua_stack_test.cc \
lua_test_common.h \
sfip_test.cc \
sfrf_test.cc \
sfrt_test.cc \
sfthd_test.cc \
unit_test.cc \
unit_test.h \
$(BUILT_SOURCES)

suite_decl.h:
	$(srcdir)/build_decl.sh $(top_srcdir) $(srcdir)

suite_list.h:
	$(srcdir)/build_list.sh $(top_srcdir) $(srcdir)

