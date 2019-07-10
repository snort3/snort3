#!/bin/sh
# Check configuration file provided by snort.conf upstrea
# to detect rules files which are not available

set -e

CONFIG="etc/snort.conf" 
errval=0

if [ ! -e "$CONFIG" ] ; then
    echo "ERROR: configuration file $CONFIG does not exist" >&2
    exit 1
fi

if [ ! -d "rules" ] ; then
    echo "ERROR: Rules subdirectory does not exist" >&2
    exit 1
fi

# Review the rules which are enabled but do not exist
cat $CONFIG  | grep -v ^# | egrep 'include \$RULE_PATH.*\.rules$' | awk -F "/" '{print $2}' |
while read rules_file; do
    if [ ! -e "rules/$rules_file" ] ; then
        echo "ERROR: Rules file $rules_file in configuration file does not exist under rules/"  >&2
        errval=1
    fi
done

# Review the rules which are disabled but *do* exist
cat $CONFIG  | grep ^# | egrep 'include \$RULE_PATH.*\.rules$' | awk -F "/" '{print $2}' |
while read rules_file; do
    if [ -e "rules/$rules_file" ] ; then
        echo "WARN: Rules file $rules_file disabled in configuration file but exists under rules/"  >&2
    fi
done

exit $errval
