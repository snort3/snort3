#!/usr/bin/env bash
# Generate the CMake files required to build all piglet plugins (prefixed with pp_*) 
# in this directory. Should be run whenever a new piglet plugin is added.
# This script needs to be run in the piglet plugins directory.

declare -a SOURCES
SOURCES=$(ls pp_*.cc)

# cmake
# =====
cat > pp_static_sources.cmake <<EOF
set (PP_STATIC_SOURCES
${SOURCES[@]}
)
EOF

rm -f pp_shared_libraries.cmake
for source in ${SOURCES[@]}; do
  echo "add_shared_library(${source%.cc} piglet_plugins ${source})" \
    >> pp_shared_libraries.cmake
done


# piglet_plugins.cc
# =================
declare -a BASENAMES
for item in ${SOURCES[@]}; do
  BASENAMES+=(${item%.cc})
done

cat > piglet_plugins.cc <<EOF
#include "piglet_plugins.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef STATIC_PIGLETS

EOF

for item in ${BASENAMES[@]}; do
  echo "extern const BaseApi* ${item};" >> piglet_plugins.cc
done

cat >> piglet_plugins.cc <<EOF

#endif

const struct BaseApi* piglets[] = {
#ifdef STATIC_PIGLETS

EOF

for item in ${BASENAMES[@]}; do echo "    ${item}," >> piglet_plugins.cc; done
cat >> piglet_plugins.cc <<EOF

#endif
    nullptr
};
EOF
