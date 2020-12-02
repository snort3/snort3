#!/bin/sh

src=$1/$2.lua
tag=$2

echo "static const char* lua_$tag = R\"[$tag]("
cat $src
echo ")[$tag]\";"

