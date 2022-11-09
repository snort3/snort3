#!/usr/bin/env bash
# run from top of source tree (where configure.ac lives)
# or supply top_srcdir as argument
# use ./snort_devel.html to browse the source notes and headers
#
# FIXIT:
# -- make sidebar width draggable
# -- remove header guards?  (outermost #ifndef, #define, #endif)
# -- use css source instead of the sed fixups?

usage()
{
    echo "usage: $0 [<top_srcdir>]"
    exit -1
}

pushd .
work=`pwd`

if [ "$1" ] ; then
    cd $1 || usage
    echo "cd $1"
fi

[ -d src ] || usage

out=snort_devel.txt
data=dev_data.txt
html=snort_devel.html
notes=dev_notes.txt
more_notes=dev_notes_*.txt

src_dirs=`find src -type d -name "[^.]?*" | sort`

# copy headers to temp working dir using same tree structure
# but strip out repetitive copyright blocks

for d in $src_dirs ; do
    mkdir -p $work/$d

    ls $d/*.h &> /dev/null ||
        continue

    for f in $d/*.h ; do
        n=`grep -m 1 -n -o "#ifndef" $f`
        n=${n/:*}
        [ "$n" ] || continue
        n=$((n-1))
        sed -e "1,${n}d" $f > $work/$f
    done
done

echo "generating doc source from headers and dev notes"

for d in $src_dirs ; do

    # section heading
    if [ ${#d} -eq 3 ] ; then
        echo -e "=== $d/\n"
    else
        echo -e "=== ${d:4}/\n"
    fi

    # section notes
    if [ -e "$d/$notes" ] ; then
        cp $d/$notes $work/$d/
        cp $d/$more_notes $work/$d/
        echo -e "include::$d/$notes[]\n"
    fi

    ls $d/*.h &> /dev/null ||
        continue

    # now emit subsection for all headers
    for h in $d/*.h ; do
        [ -e "$work/$h" ] || continue
        cat <<END
==== ${h/$d\//}
~Path = ${h}~

[source,cpp]
-----------------------
include::$h[]
-----------------------

END
    done
done >> $work/$data

echo "generating the dev guide"
popd
asc_args="-b xhtml11 -a toc2"
asciidoc $asc_args $out

# fix up some stuff
# this is quick and dirty and but not future proof
echo "fixing up the html"

sed -i.sed \
    -e "s/color: fuchsia/color: green/" \
    -e "s/margin-left: 16em/margin-left: 20em/" \
    -e "s/width: 13em/width: 18em/" \
    $html

# now convert snort includes into links using the existing anchor points
# we can't derive the href ids because the toc generator only uses the
# file w/o path (eg _rules_h instead of _detection_rules_h) and will add
# numeric suffixes if non-unique (foo/rules.h and bar/rules.h would become
# _rules_h and _rules_h_2).

# this function generates sed commands like this
# s|"detection/rules.h"|<a href=#_rules_h>"detection/rules.h"</a>|
# for each Path added above

gen_cmds()
{
    while true ; do
        read id
        id=${id/*=\"/}
        id=${id/\"*/}

        read path
        path=${path/*Path = /}
        path=${path/\<*/}
        path=\"${path:4}\"

        echo "s|$path|<a href=#$id>$path</a>|"

        if ! read sep ; then
            break
        fi
    done
}

echo "generating link commands"
grep -B 1 "Path = " $html | gen_cmds > sed_cmds.txt

echo "translating snort includes into links"
sed -i.sed -f sed_cmds.txt $html

