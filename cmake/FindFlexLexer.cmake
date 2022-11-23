
find_package(FLEX 2.6.0 REQUIRED)

find_path(FLEX_INCLUDES "FlexLexer.h"
    HINTS ${FLEX_INCLUDE_DIR_HINT}
    PATHS ${FLEX_INCLUDE_DIRS}
    REQUIRED
)

mark_as_advanced(FLEX_INCLUDES)

macro(FLEX NAME LEXER_IN LEXER_OUT)
    FLEX_TARGET(${NAME}
        ${LEXER_IN}
        ${LEXER_OUT}.tmp
        COMPILE_FLAGS ${FLEX_FLAGS}
    )

    # we use '+' as a separator for 'sed' to avoid conflicts with '/' in paths from LEXER_OUT
    add_custom_command(
        OUTPUT ${LEXER_OUT}
        COMMAND sed -e
            "s+void yyFlexLexer::LexerError+yynoreturn void yyFlexLexer::LexerError+;s+${LEXER_OUT}.tmp+${LEXER_OUT}+"
            ${FLEX_${NAME}_OUTPUTS} > ${LEXER_OUT}
        DEPENDS ${FLEX_${NAME}_OUTPUTS}
        VERBATIM
    )

    set(${NAME}_OUTPUTS ${LEXER_OUT})
endmacro()
