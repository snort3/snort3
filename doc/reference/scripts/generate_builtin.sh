#!/usr/bin/env bash

SNORT_BINARY="$1"
INPUT_FILE="$2"
OUTPUT_FILE="$3"
PLUGIN_PATH="$4"

PLUGIN_ARGS=

if [ -n "${PLUGIN_PATH}" ] ; then
  PLUGIN_ARGS="--plugin-path=${PLUGIN_PATH}"
fi

cp ${INPUT_FILE} ${OUTPUT_FILE}

${SNORT_BINARY} ${PLUGIN_ARGS} --list-builtin | while read line ; do \
    gidsid="${line/ *}"; \
    msg="${line#* }"; \
    msg="${msg//\//\\/}"; \
    sed -i -e "s/^$gidsid\$/\*$gidsid $msg\*/" ${OUTPUT_FILE}; \
done

