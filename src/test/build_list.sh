#!/bin/bash

SOURCE_DIR=$1
FILE=$2/suite_list.h

rm -f $FILE ;
for f in `grep -whoR --include \*.cc 'TEST_SUITE[^(]*' $SOURCE_DIR` ; do
    echo "$f," >> $FILE ;
done ;
touch unit_test.cc
