AUTOMAKE_OPTIONS=foreign no-dependencies

docdir = ${prefix}/doc

BUILT_SOURCES = \
builtin.txt \
commands.txt \
config.txt \
gids.txt \
options.txt \
version.txt

unbuilt_sources = \
snort_manual.txt \
differences.txt \
plugins.txt \
style.txt \
tips.txt \
images/snort.png

all_sources = \
$(unbuilt_sources) \
$(BUILT_SOURCES)

dist_doc_DATA = \
$(unbuilt_sources)

if MAKE_HTML_DOC
EXTRA_DIST = \
snort_manual.html \
snort_manual.tgz \
images.tgz

if MAKE_PDF_DOC
EXTRA_DIST += \
snort_manual.pdf
endif
endif

dist_doc_DATA += $(EXTRA_DIST)

snort = $(top_srcdir)/src/snort

builtin.txt: $(snort)
	$(snort) --markup --help-builtin | sort -n -t : -k 1.4 -k 2 > $@

commands.txt: $(snort)
	$(snort) --markup --help-commands | sort > $@

config.txt: $(snort)
	$(snort) --markup --help-config | sort -k 3 > $@

gids.txt: $(snort)
	$(snort) --markup --help-gids | sort -n  -k 1.4 > $@

options.txt: $(snort)
	$(snort) --markup --help-options | sort > $@

version.txt: $(snort)
	$(snort) -V 2>&1 | grep -v Using > $@

pdf_args = \
    --icons --icons-dir=./images/icons \
    -a imagesdir=./images

html_args = \
    --copy --attribute linkcss --attribute stylesdir \
    --attribute disable-javascript --attribute quirks! \
	$(pdf_args)

# this is the docbook approach to html
#snort_manual.html: snort_manual.txt $(all_sources)
#	a2x -f xhtml $(html_args) $<

# this is the asciidoc direct approach to hmtl
# FIXIT no fuschia for visited; all should be sans serif
# extracted asciidoc.css doesn't seem to work with -a linkcss
snort_manual.html: snort_manual.txt $(all_sources)
	asciidoc -b xhtml11 -a toc2 -a icons -a imagesdir=./images $<

snort_manual.pdf: snort_manual.txt $(all_sources)
	a2x -f pdf $(pdf_args) $<

snort_manual.tgz: snort_manual.txt $(all_sources)
	a2x -f chunked $(html_args) $<
	tar zcf $@ -C snort_manual.chunked .

images.tgz: images/
	tar zcf $@ \
        -C images \
        --exclude callouts \
        --exclude README \
        .

clean-local:
	rm -f *.tgz
	rm -f snort_manual.{fo,xml,html,pdf}
	rm -rf snort_manual.chunked/
	rm -f *.css

