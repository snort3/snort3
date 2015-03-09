AUTOMAKE_OPTIONS=foreign no-dependencies

BUILT_SOURCES = \
builtin.txt \
commands.txt \
config.txt \
counts.txt \
gids.txt \
help.txt \
modules.txt \
options.txt \
plugins.txt \
signals.txt \
version.txt \
basic.txt \
codec.txt \
data.txt \
inspector.txt \
ips_action.txt \
ips_option.txt \
logger.txt  \
snort2lua_cmds.txt

# currently no modules for these
#search_engine.txt
#so_rule.txt

unbuilt_sources = \
snort_manual.txt \
config_changes.txt \
differences.txt \
enviro.txt \
errors.txt \
extending.txt \
features.txt \
overview.txt \
params.txt \
reference.txt \
snort2lua.txt \
snorty.png \
start.txt \
style.txt \
terms.txt \
usage.txt

all_sources = \
$(unbuilt_sources) \
$(BUILT_SOURCES)

EXTRA_DIST = \
default_snort_manual.html \
default_snort_manual.pdf

doc_DATA = \
snort_manual.html \
snort_manual.pdf

dist_doc_DATA = \
$(all_sources)

snort = $(top_builddir)/src/snort
snort2lua = $(top_builddir)/tools/snort2lua/snort2lua
plugin_path = $(if $(shell echo $$SNORT_PLUGIN_PATH), --plugin-path=$$SNORT_PLUGIN_PATH )

FORCE:
$(unbuilt_sources): FORCE
	[ "$(srcdir)/$@" = "$(builddir)/$@" -o $(srcdir)/$@ -ot $(builddir)/$@ ] || \
		cp $(srcdir)/$@ $(builddir)/$@

builtin.txt: $(snort)
	$(snort) $(plugin_path) --markup --list-builtin | sort -n -t : -k 1.4 -k 2 > $@

commands.txt: $(snort)
	$(snort) $(plugin_path) --markup --help-commands | sort > $@

config.txt: $(snort)
	$(snort) $(plugin_path) --markup --help-config | sort -k 3 > $@

counts.txt: $(snort)
	$(snort) $(plugin_path) --markup --help-counts | sort -k 2 > $@

gids.txt: $(snort)
	$(snort) $(plugin_path) --markup --list-gids | sort -n  -k 1.4 > $@

modules.txt: $(snort)
	$(snort) $(plugin_path) --markup --help-modules > $@

plugins.txt: $(snort)
	$(snort) $(plugin_path) --markup --help-plugins > $@

help.txt: $(snort)
	$(snort) --help > $@

basic.txt: $(snort)
	for m in `$(snort) --list-modules basic` ; do \
		$(snort) --markup --help-module $$m ; \
	done > $@

codec.txt: $(snort)
	for m in `$(snort) --list-modules codec` ; do \
		$(snort) $(plugin_path)  --markup --help-module $$m ; \
	done > $@

data.txt: $(snort)
	for m in `$(snort) --list-modules data` ; do \
		$(snort) $(plugin_path) --markup --help-module $$m ; \
	done > $@

inspector.txt: $(snort)
	for m in `$(snort) --list-modules inspector` ; do \
		$(snort) $(plugin_path) --markup --help-module $$m ; \
	done > $@

ips_action.txt: $(snort)
	for m in `$(snort) --list-modules ips_action` ; do \
		$(snort) $(plugin_path) --markup --help-module $$m ; \
	done > $@

ips_option.txt: $(snort)
	for m in `$(snort) --list-modules ips_option` ; do \
		$(snort) $(plugin_path) --markup --help-module $$m ; \
	done > $@

logger.txt: $(snort)
	for m in `$(snort) --list-modules logger` ; do \
		$(snort) $(plugin_path) --markup --help-module $$m ; \
	done > $@

#search_engine.txt: $(snort)
#	for m in `$(snort) --list-modules search_engine` ; do \
#		$(snort) $(plugin_path) --markup --help-module $$m ; \
#	done > $@

#so_rule.txt: $(snort)
#	for m in `$(snort) --list-modules so_rule` ; do \
#		$(snort) $(plugin_path) --markup --help-module $$m ; \
#	done > $@

options.txt: $(snort)
	$(snort) --markup --help-options | sort > $@

signals.txt: $(snort)
	$(snort) --markup --help-signals | sort > $@

version.txt: $(snort)
	$(snort) -V 2>&1 | grep -v Using > $@

snort2lua_cmds.txt: $(snort2lua)
	$(snort2lua) --markup --help > $@

pdf_args = -a imagesdir=.

html_args = \
    --copy --attribute linkcss --attribute stylesdir \
    --attribute disable-javascript --attribute quirks! \
	--xsltproc-opts="--stringparam chunk.tocs.and.lots 1" \
	$(pdf_args)

if MAKE_HTML_DOC
# FIXIT no fuschia for visited; all should be sans serif
# extracted asciidoc.css doesn't seem to work with -a linkcss
# asciidoc native html generation; buggy passthru of base64 data
snort_manual.html: $(all_sources)
	asciidoc -b xhtml11 -a toc2 -a icons -a imagesdir=. $<
	a2x -f chunked $(html_args) $<
else
snort_manual.html: default_snort_manual.html
	cp $< $@
endif

if MAKE_PDF_DOC
snort_manual.pdf: snort_manual.txt $(all_sources) snort_manual.html
	a2x -f pdf $(pdf_args) $<
else
snort_manual.pdf: default_snort_manual.pdf
	cp $< $@
endif

if MAKE_HTML_DOC
install-data-hook:
	cp -R $(builddir)/snort_manual.chunked $(DESTDIR)$(docdir)/

uninstall-hook:
	rm -rf $(DESTDIR)$(docdir)/snort_manual.chunked
endif

delete_unbuilt = $(if $(and $(findstring $(builddir),$(srcdir)),$(findstring $(srcdir),$(builddir))), ,$(unbuilt_sources))

clean-local:
	rm -f $(BUILT_SOURCES)
	rm -f $(delete_unbuilt)
	rm -f snort_manual.{fo,xml,html,pdf}
	rm -rf snort_manual.chunked
	rm -f *.css *.tgz

