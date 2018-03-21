#!/usr/bin/env bash
# run from top of source tree (where configure.ac lives)
# or supply top_srcdir as argument
# this will create /tmp/dev_guide.{txt,html}
# use ./dev_guide.html to browse the source notes and headers
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

if [ "$1" ] ; then
    cd $1 || usage
    echo "cd $1"
fi

[ -d src ] || usage

tmp=/tmp/dev_guide/
out=$tmp/dev_guide.txt
html=$tmp/dev_guide.html
notes=dev_notes.txt

echo "generating working tree in $tmp"
mkdir -p $tmp || exit -1

src_dirs=`find src -type d -name "[^.]?*"`

# copy headers to temp working dir using same tree structure
# but strip out repetitive copyright blocks

for d in $src_dirs ; do
    mkdir -p $tmp/$d

    ls $d/*.h &> /dev/null ||
        continue

    for f in $d/*.h ; do
        n=`grep -m 1 -n -o "#ifndef" $f`
        n=${n/:*}
        [ "$n" ] || continue
        n=$((n-1))
        sed -e "1,${n}d" $f > $tmp/$f
    done
done

echo "generating doc source from headers and dev notes"

# emit doc boilerplate
cat <<END > $out
= Snort++ Developers Guide
:author: The Snort Team
:toc:
:toc-placement: manual
:toc-title: Contents

toc::[]

END

# emit copyright just once at the top
sed -ne "1,/^$/s/..//p" src/main.h >> $out
echo >> $out

for d in $src_dirs ; do

    # section heading
    if [ ${#d} -eq 3 ] ; then
        echo -e "== $d/\n"
    else
        echo -e "== ${d:4}/\n"
    fi

    # section notes
    if [ -e "$d/$notes" ] ; then
        cp $d/$notes $tmp/$d/
        echo -e "include::$d/$notes[]\n"
    fi

    ls $d/*.h &> /dev/null ||
        continue

    # now emit subsection for all headers
    for h in $d/*.h ; do
        [ -e "$tmp/$h" ] || continue
        cat <<END
=== ${h/$d\//}
~Path = ${h}~

[source,cpp]
-----------------------
include::$h[]
-----------------------

END
    done
done >> $out

echo "generating the dev guide from the source in $tmp"
cd $tmp
asc_args="-b xhtml11 -a toc2"
asciidoc $asc_args $out

# this results in:
#a2x_args="--copy -a linkcss -a stylesdir -a disable-javascript -a quirks! --xsltproc-opts='--stringparam chunk.tocs.and.lots 1'"
#
# Usage: a2x [OPTIONS] SOURCE_FILE
#
#a2x: error: incorrect number of arguments

# this results in:
a2x_args="--copy -a linkcss -a stylesdir -a disable-javascript -a quirks!"

# a2x: ERROR: "dblatex" -t pdf -p
# "/opt/local/etc/asciidoc/dblatex/asciidoc-dblatex.xsl" -s
# "/opt/local/etc/asciidoc/dblatex/asciidoc-dblatex.sty"
# "/Users/rucombs/Build/auto/doc/tmp/dev_guide.xml" returned non-zero exit
# status 1
#a2x -f chunked $a2x_args $out

# and this doesn't syntax highlight:
#a2x -f pdf $a2x_args $out

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

echo "clean up"
popd
mv $html ./
rm -rf $tmp

echo "done; see ./dev_guide.html"

