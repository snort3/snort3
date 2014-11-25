# - Find Asciidoc
# this module looks for asciidoc
#
# ASCIIDOC_A2X_EXE - the full path to asciidoc's a2x
# ASCIIDOC_EXE -  the full path to asciidoc's asciidoc command
# Asciidoc_FOUND - If false, don't attempt to use asciidoc.

set(ERROR_MESSAGE
    "Unable to find Asciidoc.  Dowbnload and install AsciiDoc to create
     custom documentation"
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
