#!/bin/bash

SOURCE_DIR=$1
FILE=$2/suite_list.h

# delete file to rebuild
[ -e $FILE ] && exit

echo "adding TEST_SUITEs to list"

for f in `grep -whoR --include \*.cc 'TEST_SUITE[^(]*' $SOURCE_DIR` ; do
    echo "$f," >> $FILE
done

