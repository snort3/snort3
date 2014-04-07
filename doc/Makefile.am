AUTOMAKE_OPTIONS=foreign no-dependencies

docdir = ${prefix}/doc

BUILT_SOURCES = \
builtin.txt \
commands.txt \
config.txt \
gids.txt \
options.txt

unbuilt_sources = \
snort_manual.txt \
differences.txt \
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

options.txt: $(top_srcdir)/src/snort
	../src/snort --markup --help > $@

config.txt: $(top_srcdir)/src/snort
	../src/snort --markup --help-config > $@

builtin.txt: $(top_srcdir)/src/snort
	../src/snort --markup --help-builtin > $@

gids.txt: $(top_srcdir)/src/snort
	../src/snort --markup --help-gids > $@

commands.txt: $(top_srcdir)/src/snort
	../src/snort --markup --help-commands > $@

pdf_args = \
    --icons --icons-dir=./images/icons \
    -a imagesdir=./images

html_args = \
    --copy --attribute linkcss --attribute stylesdir \
    --attribute disable-javascript --attribute quirks! \
	$(pdf_args)

snort_manual.html: snort_manual.txt $(all_sources)
	a2x -f xhtml $(html_args) $<

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

