
AM_DEFAULT_SOURCE_EXT = .cc

check_PROGRAMS = \
http_uri_norm_test \
http_normalizers_test \
http_module_test \
http_transaction_test \
http_msg_head_shared_util_test

TESTS = $(check_PROGRAMS)

http_uri_norm_test_CPPFLAGS = $(AM_CPPFLAGS) @CPPUTEST_CPPFLAGS@
http_uri_norm_test_LDADD = \
../http_uri_norm.o \
../http_module.o \
../http_test_manager.o \
../http_test_input.o \
../http_normalizers.o \
../http_str_to_code.o \
../http_field.o \
../http_tables.o \
../../../framework/module.o \
@CPPUTEST_LDFLAGS@

http_normalizers_test_CPPFLAGS = $(AM_CPPFLAGS) @CPPUTEST_CPPFLAGS@
http_normalizers_test_LDADD = \
../http_normalizers.o \
../http_field.o \
@CPPUTEST_LDFLAGS@

http_module_test_CPPFLAGS = $(AM_CPPFLAGS) @CPPUTEST_CPPFLAGS@
http_module_test_LDADD = \
../http_module.o \
../http_tables.o \
../http_normalizers.o \
../http_uri_norm.o \
../http_field.o \
../../../framework/module.o \
@CPPUTEST_LDFLAGS@

http_transaction_test_CPPFLAGS = $(AM_CPPFLAGS) @CPPUTEST_CPPFLAGS@
http_transaction_test_LDADD = \
../http_transaction.o \
../http_flow_data.o \
../http_test_manager.o \
../http_test_input.o \
@CPPUTEST_LDFLAGS@

http_msg_head_shared_util_test_CPPFLAGS = $(AM_CPPFLAGS) @CPPUTEST_CPPFLAGS@
http_msg_head_shared_util_test_LDADD = \
../http_msg_head_shared_util.o \
../http_field.o \
../http_str_to_code.o \
@CPPUTEST_LDFLAGS@


