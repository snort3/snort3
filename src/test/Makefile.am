AUTOMAKE_OPTIONS=foreign no-dependencies

noinst_LIBRARIES = libtest.a

libtest_a_SOURCES = \
sfip_test.cc \
sfrf_test.cc \
sfrt_test.cc \
sfthd_test.cc \
unit_test.cc \
unit_test.h

BUILT_SOURCES = \
suite_decl.h \
suite_list.h

.PHONY: suite_decl.h
.PHONY: suite_list.h

build_decl = \
    rm -f suite_decl.h ; \
    for f in `grep -whoR --include \*.cc 'TEST_SUITE[^(]*' $(top_srcdir)/src` ; do \
	    echo "extern Suite* $$f();" >> suite_decl.h ; \
    done ; \
	touch $(srcdir)/unit_test.cc

build_list = \
    rm -f suite_list.h ; \
    for f in `grep -whoR --include \*.cc 'TEST_SUITE[^(]*' $(top_srcdir)/src` ; do \
        echo "$$f," >> suite_list.h ; \
    done ; \
	touch $(srcdir)/unit_test.cc

suite_decl.h:
	$(build_decl)

suite_list.h:
	$(build_list)

AM_CXXFLAGS = @AM_CXXFLAGS@

