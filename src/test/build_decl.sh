#/bin/bash

SOURCE_DIR=$1
FILE=$2/suite_decl.h

# delete file to rebuild
[ -e $FILE ] && exit

echo "adding TEST_SUITE declarations"

for f in `grep -whoR --include \*.cc 'TEST_SUITE[^(]*' $SOURCE_DIR` ; do
    echo "extern Suite* $f();" >> $FILE
done

