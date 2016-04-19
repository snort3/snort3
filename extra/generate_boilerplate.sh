#!/bin/bash

USAGE="Usage: $0 <start> <expander:./scripts> <templates:./templates>"

if [[ $1 == -h ]]; then
  echo $USAGE >&2
  exit
fi

RECURSE=${1:-$PWD}
SCRIPT_PATH=./scripts
TEMPLATE_PATH=./templates

EXPAND=${SCRIPT_PATH}/expand_template.rb

boilerplate=(
  ${TEMPLATE_PATH}/CMakeLists.txt.erb
  ${TEMPLATE_PATH}/Makefile.am.erb
)

[[ -n $DRY_RUN ]] && ECHO=echo || ECHO=

for item in $(find $RECURSE -name '*.cc'); do
  item_dirpath=$(dirname $item)
  item_dir=${item_dirpath##*/}
  item_base=${item##*/}

  if [[ $item_dir != ${item_base%.cc} ]]; then
    continue
  fi

  for template in "${boilerplate[@]}"; do
    base=${template##*/}
    [[ -n $DRY_RUN ]] && \
      echo $EXPAND $template $item_dirpath '>' $item_dirpath/${base%.erb} || \
      $EXPAND $template $item_dirpath > $item_dirpath/${base%.erb}
  done
done
