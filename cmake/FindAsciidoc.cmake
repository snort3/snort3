# - Find Asciidoc
# this module looks for asciidoc, a2x, and w3m
# the asciidoc package includes both asciidoc and a2x
#
# asciidoc, a2x, w3m:
# *_EXE -  the full path to the above command
# *_FOUND - if false, don't attempt to use above command

# to build:
# html (single or chunked) - asciidoc needed
# text - asciidoc and w3m needed
# pdf - asciidoc and dblatex needed

set(ERROR_MESSAGE
    "install asciidoc to build the html user manual"
)

FIND_PROGRAM(ASCIIDOC_EXE asciidoc)
find_program(ASCIIDOC_A2X_EXE a2x)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Asciidoc
    REQUIRED_VARS ASCIIDOC_A2X_EXE ASCIIDOC_EXE
    FAIL_MESSAGE "${ERROR_MESSAGE}"
)

mark_as_advanced(
    ASCIIDOC_EXE
    ASCIIDOC_A2X_EXE
)

find_program(W3M_EXE w3m)

find_package_handle_standard_args(W3M
    REQUIRED_VARS W3M_EXE
    FAIL_MESSAGE "install w3m to build all-in-one text user manual"
)

mark_as_advanced(W3M_EXE)

