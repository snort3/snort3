#!/bin/sh

cat << EOF
ffi = require("ffi")
ffi.cdef[[
$(grep -v -e '^ *//' -e '^ *#' -e '^ *extern "C"' $1)
]]
EOF
