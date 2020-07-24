#!/bin/sh

SNORT_BINARY="$1"
OUTPUT_FILE="$2"
PLUGIN_PATH="$3"
PLUGIN_ARGS=

if [ -n "${PLUGIN_PATH}" ] ; then
  PLUGIN_ARGS="--plugin-path=${PLUGIN_PATH}"
fi

MODULE_TYPE=`basename "${OUTPUT_FILE}" .txt`

rm -f "${OUTPUT_FILE}"

"${SNORT_BINARY}" ${PLUGIN_ARGS} --list-modules "${MODULE_TYPE}" \
  | while read module_name; do

  "${SNORT_BINARY}" ${PLUGIN_ARGS} --markup --help-module "${module_name}" \
    >> "${OUTPUT_FILE}"

done
