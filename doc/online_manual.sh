#!/bin/sh

# run this from build/doc/ to create an all in one html manual
# with embedded images in base64 format for use in places where
# the image links aren't supported.

input="snort_manual"
output="snort_online"
data="images.dat"

make_names ()
{
    pfx="${1%.png}"
    img="$pfx.img"
    b64="$pfx.b64"
}

make_img ()
{
    cat > $2 << END
++++
<img alt="$1" src="data:image/png;base64,
$2
" />
++++
END
}

make_ex ()
{
    ex $input.html << END
/$1
r $2
/$1
d
wq
END
}

# create working dir
mkdir tmp || exit 1
cd tmp

# copy the sources since we need to make edits
cp ../*.txt ../*.png ./

# create a list of 'txt png' pairs
grep -o 'image::.*.png' *.txt > $data
sed -i.sed -e " s/:image::/ /" $data

# preprocess
cat $data | while read txt png ; do
    make_names $png

    #echo "preprocess $txt $png $pfx $img $b64"

    # get the raw base64 data file
    # different options on osx linux :(
    opt="w"
    base64 --help | grep -q "\-b" && opt="b"

    base64 -$opt 80 < $png > $b64

    # put this stub image tag into an include file
    make_img $pfx $img

    # make a version of the source that includes the above file
    sed -i.sed -e " s/^image::$png.*/include::$img[]/" $txt
done

# generate the toc2 html with stub tag
asciidoc -b xhtml11 -a toc2 -a icons $input.txt

# postprocess
cat $data | while read txt png ; do
    make_names $png

    #echo "postprocess $txt $png $pfx $img $b64"

    # edit online.html and put snort.b64 into the image tag
    make_ex $img $b64
done

# clean up the mess
mv $input.html ../$output.html
cd ..
rm -rf ./tmp/

