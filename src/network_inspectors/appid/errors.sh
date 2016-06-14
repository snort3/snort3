#!/bin/bash

# run make on selected files from MANIFEST.txt

USAGE="$0 [-h] [<status>] [<cisco_username>]"

if [[ $1 == -h ]]; then
  echo $USAGE >&2
  exit
fi

file_status=$1
cisco_username=$2
filter=

if [[ -n "$file_status" ]]; then
  filter="$filter *$file_status"
fi

if [[ -n "$cisco_username" ]]; then
  filter="$filter *$USER"
fi

grep -v ^# MANIFEST.txt | while IFS='' read -r line || [[ -n "$line" ]]; do
  echo $line | grep "$filter" >/dev/null && {
    filename=$(echo $line | awk '{print $1}')
    make "${filename%.*}_${filename##*.}" >/dev/null || echo $filename
  }
done
