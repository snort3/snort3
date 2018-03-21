#!/bin/sh

SNORT_BINARY="$1"
OUTPUT_FILE="$2"
PLUGIN_PATH="$3"
HELP_ARG="--help"
PLUGIN_ARGS=
SORT_ARGS=

if [ -n "${PLUGIN_PATH}" ] ; then
  PLUGIN_ARGS="--plugin-path=${PLUGIN_PATH}"
fi

HELP_TYPE=`basename "${OUTPUT_FILE}" .txt`

if [ "${HELP_TYPE}" != "help" ] ; then
  HELP_ARG="${HELP_ARG}-${HELP_TYPE}"

  case "${HELP_TYPE}" in
    config)
      SORT_ARGS="-k 3"
      ;;
    counts)
      SORT_ARGS="-k 2"
      ;;
  esac
fi

if [ -n "${SORT_ARGS}" ] ; then
  "${SNORT_BINARY}" ${PLUGIN_ARGS} --markup "${HELP_ARG}" | sort ${SORT_ARGS} \
    > "${OUTPUT_FILE}"
else
  "${SNORT_BINARY}" ${PLUGIN_ARGS} --markup "${HELP_ARG}" \
    > "${OUTPUT_FILE}"
fi
