#!/bin/sh

cxx=$1
src=$2
dirs=$3

plugs=framework/plugins.h

cd $src/..

echo "// the set of versioned headers installed by Snort"
echo "// this file is generated automatically - do not edit"
echo "// see framework/plugins.h for details"
echo

$cxx -MM $plugs $dirs | \
    sed -e "s/ /\n/g" | \
    grep ".*.h$" | grep -v "$plugs" | \
    sed -e "s/^/#include \"/" -e "s/$/\"/" -e 's/.*api_options.h.*/#include "framework\/api_options.h"/' | \
    sort

