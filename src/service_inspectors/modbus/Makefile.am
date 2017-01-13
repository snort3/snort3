
file_list = \
ips_modbus_data.cc \
ips_modbus_func.cc \
ips_modbus_unit.cc \
modbus.cc \
modbus.h \
modbus_decode.cc \
modbus_decode.h \
modbus_module.cc \
modbus_module.h \
modbus_paf.cc \
modbus_paf.h

if STATIC_INSPECTORS
noinst_LIBRARIES = libmodbus.a
libmodbus_a_SOURCES = $(file_list)
else
shlibdir = $(pkglibdir)/inspectors
shlib_LTLIBRARIES = modbus.la
modbus_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
modbus_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
modbus_la_SOURCES = $(file_list)
endif

EXTRA_DIST = dev_notes.txt
