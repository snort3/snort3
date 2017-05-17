
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
connector.txt \
inspector.txt \
ips_action.txt \
ips_option.txt \
logger.txt  \
snort2lua_cmds.txt \
search_engine.txt

# currently no modules for these
#so_rule.txt

unbuilt_sources = \
appid.txt \
binder.txt \
bugs.txt \
building.txt \
byte_extract.txt \
byte_jump.txt \
byte_math.txt \
byte_test.txt \
concepts.txt \
config_changes.txt \
connectors.txt \
daq.txt \
daq_readme.txt \
dcerpc.txt \
differences.txt \
enviro.txt \
errors.txt \
extending.txt \
features.txt \
file_processing.txt \
high_availability.txt \
http_inspect.txt \
overview.txt \
params.txt \
perf_monitor.txt \
reference.txt \
sensitive_data.txt \
side_channel.txt \
snort2lua.txt \
snort2x.png \
snort3x.png \
snort_manual.txt \
snorty.png \
style.txt \
terms.txt \
testing_numerical_values.txt \
tutorial.txt \
usage.txt \
wizard.txt

all_sources = \
$(unbuilt_sources) \
$(BUILT_SOURCES)

EXTRA_DIST = \
snort_manual.text \
snort_manual.html \
snort_manual.pdf \
online_manual.sh \
dev_guide.sh

dist_doc_DATA = \
$(unbuilt_sources)

snort = $(top_builddir)/src/snort
snort2lua = $(top_builddir)/tools/snort2lua/snort2lua
plugin_path = $(if $(shell echo $$SNORT_PLUGIN_PATH), --plugin-path=$(SNORT_PLUGIN_PATH) )

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
	for m in `$(snort) $(plugin_path) --list-modules codec` ; do \
		$(snort) $(plugin_path)  --markup --help-module $$m ; \
	done > $@

connector.txt: $(snort)
	for m in `$(snort) $(plugin_path) --list-modules connector` ; do \
		$(snort) $(plugin_path)  --markup --help-module $$m ; \
	done > $@

inspector.txt: $(snort)
	for m in `$(snort) $(plugin_path) --list-modules inspector` ; do \
		$(snort) $(plugin_path) --markup --help-module $$m ; \
	done > $@

ips_action.txt: $(snort)
	for m in `$(snort) $(plugin_path) --list-modules ips_action` ; do \
		$(snort) $(plugin_path) --markup --help-module $$m ; \
	done > $@

ips_option.txt: $(snort)
	for m in `$(snort) $(plugin_path) --list-modules ips_option` ; do \
		$(snort) $(plugin_path) --markup --help-module $$m ; \
	done > $@

logger.txt: $(snort)
	for m in `$(snort) $(plugin_path) --list-modules logger` ; do \
		$(snort) $(plugin_path) --markup --help-module $$m ; \
	done > $@

search_engine.txt: $(snort)
	for m in `$(snort) $(plugin_path) --list-modules search_engine` ; do \
		$(snort) $(plugin_path) --markup --help-module $$m ; \
	done > $@

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

snort_src = snort_manual.txt

pdf_args = -a imagesdir=.

html_args = \
    --copy --attribute linkcss --attribute stylesdir \
    --attribute disable-javascript --attribute quirks! \
	--xsltproc-opts="--stringparam chunk.tocs.and.lots 1" \
	$(pdf_args)

# FIXIT no fuschia for visited; all should be sans serif extracted
# asciidoc.css doesn't seem to work with -a linkcss asciidoc native html
# generation; buggy passthru of base64 data.
if MAKE_HTML_DOC
html: $(all_sources)
	a2x -f chunked $(html_args) $(snort_src)
	tar zcf snort_manual.tgz snort_manual.chunked
	asciidoc -b xhtml11 -a toc2 -a icons -a imagesdir=. $(snort_src)
endif

if MAKE_PDF_DOC
pdf: $(all_sources)
	a2x -f pdf $(pdf_args) $(snort_src)
endif

if MAKE_TEXT_DOC
text: $(all_sources)
	a2x -f text $(snort_src)
endif

if MAKE_HTML_DOC
# autotools makes doesn't seem to like directory targets, especially ones
# with an unspecified set of files.  to avoid these issues, we generate
# a tarball and then explode that upon install with a hook.  note that
# there is no default for chunked.
#
# after changing the target from all to html, exploding the tarball must
# be conditional, but install fails with this hook:
#
#install-data-hook:
#	[ -e $(builddir)/snort_manual.tgz ] && \
#		tar zxf $(builddir)/snort_manual.tgz -C $(DESTDIR)$(docdir)/
#
#uninstall-hook:
#	rm -rf $(DESTDIR)$(docdir)/snort_manual.chunked

snort_online.html: $(all_sources)
	$(srcdir)/online_manual.sh

dev_guide.html: $(snort)
	$(srcdir)/dev_guide.sh $(top_srcdir)
endif

delete_unbuilt = $(if $(and $(findstring $(builddir),$(srcdir)),$(findstring $(srcdir),$(builddir))), ,$(unbuilt_sources))

clean-local:
	rm -f $(BUILT_SOURCES)
	rm -f $(delete_unbuilt)
	rm -f snort_manual.{fo,xml}
	rm -rf snort_manual.chunked
	rm -f *.css *.tgz
	rm -f {online_manual,dev_guide}.html

