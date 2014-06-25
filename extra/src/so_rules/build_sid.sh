#!/bin/bash


FILE=$1

gzip --best --no-name --stdout $FILE.txt > $FILE.gz
xxd -i $FILE.gz > $FILE.h
