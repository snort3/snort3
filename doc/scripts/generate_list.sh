#!/bin/sh

SNORT_BINARY="$1"
OUTPUT_FILE="$2"
PLUGIN_PATH="$3"
LIST_ARG=
PLUGIN_ARGS=
SORT_OPTIONS=

if [ -n "${PLUGIN_PATH}" ] ; then
  PLUGIN_ARGS="--plugin-path=${PLUGIN_PATH}"
fi

LIST_TYPE=`basename ${OUTPUT_FILE} .txt`

case "${LIST_TYPE}" in
  gids)
    SORT_OPTIONS="-n -k 1.4"
    ;;
  builtin)
    SORT_OPTIONS="-n -t : -k 1.4 -k 2"
    ;;
esac

"${SNORT_BINARY}" ${PLUGIN_ARGS} --markup "--list-${LIST_TYPE}" \
  | sort ${SORT_OPTIONS} \
  > "${OUTPUT_FILE}"
