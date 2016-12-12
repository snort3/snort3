#!/bin/sh

cat << EOF
ffi = require("ffi")
ffi.cdef[[
$(sed -e '/^ *\/\//d' -e '/^ *#/d' -e '/^ *extern "C"/d' $1)
]]
EOF
