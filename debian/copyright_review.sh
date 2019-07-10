#!/bin/

# Review copyright statements and filter out known ones 
# (in copyright_list)

SOURCE=../src
grep -ri copyright $SOURCE |
grep -v -f copyright_list 

exit 0
