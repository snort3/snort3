#!/bin/sh

# Clean the sources
make distclean
# TODO: Consider adjusting SUBDIRS, so we do not remove the 
# doc dir
# Make sure the sources are removed (in case somebody removed the
# main Makefile but did not distclean)
(cd src &&  test -e Makefile && make distclean)

exit 0
