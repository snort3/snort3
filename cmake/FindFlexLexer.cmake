
find_package(FLEX 2.6.0 REQUIRED)

find_path(FLEX_INCLUDES "FlexLexer.h"
    HINTS ${FLEX_INCLUDE_DIR_HINT}
    PATHS ${FLEX_INCLUDE_DIRS}
    REQUIRED
)

mark_as_advanced(FLEX_INCLUDES)
