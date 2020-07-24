
add_subdirectory (user)
add_subdirectory (reference)
add_subdirectory (upgrade)
add_subdirectory (devel)

add_custom_target (
    docs-html
    DEPENDS
    docs-user-html
    docs-reference-html
    docs-upgrade-html
)

add_custom_target (
    docs-pdf
    DEPENDS
    docs-user-pdf
    docs-reference-pdf
    docs-upgrade-pdf
)

add_custom_target (
    docs-text
    DEPENDS
    docs-user-text
    docs-reference-text
    docs-upgrade-text
)

add_custom_target (
    docs-user
    DEPENDS
    docs-user-html
    docs-user-pdf
    docs-user-text
)

add_custom_target (
    docs-reference
    DEPENDS
    docs-reference-html
    docs-reference-pdf
    docs-reference-text
)

add_custom_target (
    docs-upgrade
    DEPENDS
    docs-upgrade-html
    docs-upgrade-pdf
    docs-upgrade-text
)

add_custom_target (
    docs-devel
    DEPENDS
    docs-devel-html
)

add_custom_target (
    docs
    DEPENDS
    docs-user
    docs-reference
    docs-upgrade
)

add_custom_target (
    docs-all
    DEPENDS
    docs-user
    docs-reference
    docs-upgrade
    docs-devel
)

