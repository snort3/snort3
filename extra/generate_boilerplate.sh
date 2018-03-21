#!/bin/sh

USAGE="Usage: $0 <start> <expander:./scripts> <templates:./templates>"

if [ "$1" = "-h" ]; then
  echo $USAGE >&2
  exit
fi

RECURSE=${1:-$PWD}
SCRIPT_PATH=./scripts
TEMPLATE_PATH=./templates

EXPAND=${SCRIPT_PATH}/expand_template.rb

template=${TEMPLATE_PATH}/CMakeLists.txt.erb

[ -n "$DRY_RUN" ] && ECHO=echo || ECHO=

for project_dir in $(find $RECURSE -mindepth 3 -type d); do
  project_base=${project_dir##*/}

  template_base=${template##*/}

  [ -n "$DRY_RUN" ] && \
    echo $EXPAND $template $project_dir '>' $project_dir/${template_base%.erb} || \
    $EXPAND $template $project_dir > $project_dir/${template_base%.erb}
done
