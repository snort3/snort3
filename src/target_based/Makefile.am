AUTOMAKE_OPTIONS=foreign no-dependencies

noinst_LIBRARIES = libtarget_based.a

AM_CXXFLAGS = @AM_CXXFLAGS@

#BUILT_SOURCES = \
#sf_attribute_table_parser.c \
#sf_attribute_table.h 
#sf_attribute_table.c

nodist_libtarget_based_a_SOURCES = \
sf_attribute_table_parser.c \
sf_attribute_table.h \
sf_attribute_table.c

libtarget_based_a_SOURCES = \
sftarget_reader.cc \
sftarget_reader.h \
sftarget_hostentry.cc \
sftarget_hostentry.h \
sftarget_data.h \
sftarget_protocol_reference.cc \
sftarget_protocol_reference.h \
sf_attribute_table_parser.l \
sf_attribute_table.y

.y.c:
	$(YACC) -d -psfat_ -o$@ $?

#### Ugly to get the header file built.
#### any other suggestions?
sf_attribute_table.h: sf_attribute_table.y
	$(YACC) -d -psfat_ $?
	mv y.tab.h $@

.l.c:
	$(LEX) -i -o$@ $?

sf_attribute_table_parser.c: sf_attribute_table_parser.l sf_attribute_table.h
	$(LEX) -i -Psfat -o$@ $<

clean-local:
	rm -f \
	sf_attribute_table_parser.c \
	sf_attribute_table.h \
	sf_attribute_table.c
