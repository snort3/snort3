# CHANGELOG
## 16/05/02 - **build 197**

- fix build of extras
- fix unit tests

## 16/04/29 - **build 196**

- overhaul cmake foo
- update extras to better serve as examples
- cleanup use of protocol numbers and identifiers
- continued stream_tcp refactoring
- continued dce2 port
- more static analysis memory leak fixes

## 16/04/22 - **build 195**

- added packet_capture module
- initial high availability for UDP
- changed memory_manager to use absolute instead of relative cap
- cmake and pkgconfig fixes
- updated catch headers to v1.4.0
- fix stream_tcp config leak
- added file capture stats
- static analysis updates
- DAQ interface refactoring
- perf_monitor refactoring
- unicode map file for new_http_inspect

## 16/04/08 - **build 194**

- added iterative pruning for out of memory condition
- added preemptive pruning to memory manager
- dce segmentation changes
- dce smb header checks port - non segmented packets
- added thread timing stats to perf_monitor
- fixed so rule input / output
- fixed protocol numbering issues
- fixed 129:18
- update extra version to alpha 4 - thanks to Henry Luciano
   <cuncator@mote.org> for reporting the issue
- remove legacy/unused obfuscation api
- fixed clang, gcc, and icc, build warnings
- fixed static analysis issues
- fixed memory leaks (more to go)
- clean up hyperscan pkg-config and cmake logic

## 16/03/28 - **build 193**

- fix session parsing abort handling
- fix shutdown memory leaks
- fix building against LuaJIT using only pkg-config
- fix FreeBSD build
- perf_monitor config and format fixes
- cmake - check all dependencies before fatal error
- new_http_inspect unicode initialization bug fix
- new_http_inspect %u encoding and utf 8 bare byte
- continued tcp stream refactoring
- legacy search engine cleanup
- dcd2 port continued - add dce packet fragmentation
- add configure -enable-address-sanitizer
- add configure -enable-code-coverage
- memory manager updates

## 16/03/18 - **build 192**

- use hwloc for CPU affinity
- fix process stats output
- add dce rule options iface, opnum, smb, stub_data, tcp
- add dce option for byte_extract/jump/test
- initial side channel and file connector for HA
- continued memory manager implementation
- add UTF-8 normalization for new_http_inspect
- fix rule compilation for sticky buffers
- host_cache and host_tracker config and stats updates
- miscellaneous warning and lint cleanup
- snort2Lua updates for preproc sensitive_data and sd_pattern option

## 16/03/07 - **build 191**

- fix perf_monitor stats output at shutdown
- initial port of sensitive data as a rule option
- fix doc/online_manual.sh for linux

## 16/03/04 - **build 190**

- fix console close and remote control disconnect issues
- added per-thread memcap calculation
- add statistics counters to host_tracker module
- new_http_inspect basic URI normalization with configuration options
- format string cleanup for parser logging
- fix conf reload by signal

## 16/02/26 - **build 189**

- snort2lua for dce2 port (in progress)
- replace ppm with latency
- added rule latency
- fixed more address sanitizer bugs
- fixed use of debug vs debug-msgs
- add missing ips option hash and == methods
- perf_monitor configuration
- fix linux + clang build errors
- trough rewrite

## 16/02/22 - **build 188**

- added delete/delete[] replacements for nothrow overload
  thanks to Ramya Potluri for reporting the issue
- fixed a detection option comparison bug which wasted time and space
- disable perf_monitor by default since the reporting interval should be set
- memory manager updates
- valgrind and unsanitary address fixes
- snort2lua updates for dce2
- build issue fix - make non-GNU strerror_r() the default case
- packet latency updates
- perfmon updates

## 16/02/12 - **build 187**

- file capture added - initial version writes from packet thread
- added support for http 0.9 to new_http_inspect
- added URI normalization of headers, cookies, and post bodies to new_http_inspect
- configure_cmake.sh updates to better support scripting
- updated catch header (used for some unit tests)
- continued dce2 port
- fixed misc clang and dynamic plugin build issues
- fixed static analysis issues and crash in new_http_inspect
- fixed tcp paws issue
- fixed normalization stats
- fixed issues reported by Bill Parker
- refactoring updates to tcp session
- refactoring updates to profiler

## 16/02/02 - **build 186**

- update copyright to 2016, add missing license blocks
- fix xcode builds
- fix static analysis issues
- update default manuals
- host_module and host_tracker updates
- start perf_monitor rewrite - 1st of many updates
- start dce2 port - 1st of many updates
- remove -enable-ppm - always enabled

## 16/01/25 - **build 185**

- initial host_tracker for new integrated netmap
- new_http_inspect refactoring for time and space considerations
- fix profiler depth bug
- fatal on failed IP rep segment allocation - thanks to Bill Parker
- tweaked style guide wrt class declarations

## 16/01/08 - **build 184**

- added new_http_inpsect rule options
- fixed build issue with Clang and thread_local
- continued tcp session refactoring
- fixed rule option string unescape issue

## 15/12/11 - **build 183**

- circumvent asymmetric flow handling issue

## 15/12/11 - **build 182 - Alpha 3**

- added memory profiling feature
- added regex fast pattern support
- ported reputation preprocessor from 2X
- synced to 297-262
- removed 'q' search method flavors - all are now queued
- removed PPM_TEST
- build and memory leak fixes

## 15/12/04 - **build 181**

- perf profiling enhancements
- fixed build issues and memory leaks
- continued pattern match refactoring
- fix spurious sip_method matching

## 15/11/25 - **build 180**

- ported dnp3 preprocessor and rule options from 2.X
- fixed various valgrind issues with stats from sip, imap, pop, and smtp
- fixed captured length of some icmp6 types
- added support for hyperscan search method using rule contents
   (regex to follow)
- fixed various log pcap issues
- squelch repeated ip6 ooo extensions and bad options per packet
- fixed arp inspection bug

## 15/11/20 - **build 179**

- user manaul updates
- fix perf_monitor.max_file_size default to work on 32-bit systems, thanks
   to noah_dietrich@86penny.org for reporting the issue
- fix bogus 1## 15/:431 events
- decode past excess ip6 extensions and bad options
- add iface to alert_csv.fields
- add hyperscan fast pattern search engine - functional but not yet used
- remove -enable-perf-profiling so it is always built
- perf profiling changes in preparation for memory profiling
- remove obsolete LibDAQ preprocessor conditionals
- fix arp inspection
- search engine refactoring

## 15/11/13 - **build 178**

- document runtime link issue with hyperscan on osx
- fix pathname generation for event trace file
- new_http_inspect tweaks
- remove -enable-ppm-test
- sync up auto tools and cmake build options

## 15/11/05 - **build 177**

- idle processing cleanup
- fixed teredo payload detection
- new_http_inspect cleanup
- update old http_inspect to allow spaces in uri
- added null check suggest by Bill Parker
- fix cmake for hyperscan
- ssl and dns stats updates
- fix ppm config
- miscellanous code cleanup

## 15/10/30 - **build 176**

- tcp reassembly refactoring
- profiler rewrite
- added gzip support to new_http_inspect
- added regex rule option based on hyperscan

## 15/10/23 - **build 175**

- ported gtp preprocessor and rule options from 2.X
- ported modbus preprocessor and rule options from 2.X
- fixed 116:297
- added unit test build for cmake (already in autotools builds)
- fixed dynamic builds (187 plugins, 138 dynamic)

## 15/10/16 - **build 174**

- legacy daemonization cleanup
- decouple -D, -M, -q
- delete -E
- initial rewrite of profiler
- don't create pid file unless requested
- remove pid lock file
- new_http_inspect header processing, normalization, and decompression tweaks
- convert README to markdown for pretty github rendering
   (contributed by gavares@gmail.com)
- perfmonitor fixes
- ssl stats updates

## 15/10/09 - **build 173**

- added pkt_num rule option to extras
- fix final -> finalize changes for extras
- moved alert_unixsock and log_null to extras
- removed duplicate pat_stats source from extras
- prevent tcp session restart on rebuilt packets
   thanks to rmkml for reporting the issue
- fixed profiler configuration
- fixed ppm event logging
- added filename to reload commands
- fixed -B switch
- reverted tcp syn only logic to match 2X
- ensure ip6 extension decoder state is reset for ip4 too since ip4
   packets may have ip6 next proto
- update default manuals

## 15/10/01 - **build 172**

- check for bool value before setting fastpath config option in PPM
- update manual related to liblzma
- fix file processing
- refactor non-ethernet plugins
- fix file_decomp error logic
- enable active response without flow
- update bug list

## 15/09/25 - **build 171**

- fix metadata:service to work like 2x
- fixed issues when building with LINUX_SMP
- fixed frag tracker accounting
- fix Xcode builds
- implement 116:281 decoder rule
- udpated snort2lua
- add cpputest for unit testing
- don't apply cooked verdicts to raw packets

## 15/09/17 - **build 170**

- removed unused control socket defines from cmake
- fixed build error with valgrind build option
- cleanup FLAGS use in configure.ac
- change configure.ac compiler search order to prefer clang over gcc
- update where to get dnet
- update usage and bug list
- move extra daqs and extra hext logger to main source tree
- fix breakloop in file daq
- fix plain file processing
- fix detection of stream_user and stream_file data
- log innermost proto for type of broken packets

## 15/09/10 - **build 169**

- fix chunked manual install
- add event direction bug
- fix OpenBSD build
- convert check unit tests to catch
- code cleanup
- fix dev guide builds from top_srcdir

## 15/09/04 - **build 168**

- fixed build of chunked manual (thanks to Bill Parker for reporting the issue)
- const cleanup
- new_http_inspect cookie processing updates
- fixed cmake build issue with SMP stats enabled
- fixed compiler warnings
- added unit tests
- updated error messages in u2spewfoo
- changed error format for consistency with Snort
- fixed u2spewfoo build issue
- added strdup sanity checks (thanks to Bill Parker for reporting the issue)
- DNS bug fix for TCP
- added -catch-tags [footag],[bartag] for unit test selection

## 15/08/31 - **build 167**

- fix xcode warnings

## 15/08/21 - **build 166**

- fix link error with g++ 4.8.3
- support multiple script-path args and single files
- piglet bug fixes
- add usage examples with live interfaces
   thanks to Aman Mangal <mangalaman93@gmail.com> for reporting the problem
- fixed port_scan packet selection
- fixed rpc_decode sequence number handling and buffer setup
- perf_monitor fixes for file output

## 15/08/14 - **build 165**

- flow depth support for new_http_inspect
- TCP session refactoring and create libtcp
- fix ac_sparse_bands search method
- doc and build tweaks for piglets
- expanded piglet interfaces and other enhancements
- fix unit test return value
- add catch.hpp include from https://github.com/philsquared/Catch
- run catch unit tests after check unit tests
- fix documentation errors in users manual

## 15/08/07 - **build 164**

- add range and default to command line args
- fix unit test build on osx
- DAQ packet header conditional compilation for piglet
- add make targets for dev_guide.html and snort_online.html
- cleanup debug macros
- fix parameter range for those depending on loaded plugins
   thanks to Siti Farhana Binti Lokman <sitifarhana.lokman@postgrad.manchester.ac.uk>
   for reporting the issue

## 15/07/30 - **build 163**

- numerous piglet fixes and enhancements
- BitOp rewrite
- added more private IP address
   thanks to Bill Parker for reporting the issue
- fixed endianness in private IP address check
- fix build of dynamic plugins

## 15/07/22 - **build 162**

- enable build dependency tracking
- cleanup automake and cmake foo
- updated bug list
- added Lua stack manager and updated code that manipulated a persistent lua_State
   thanks to Sancho Panza <sancho@posteo.de> for reporting the issue
- piglet updates and fixes
- dev guide - convert snort includes into links
- fixup includes

## 15/07/15 - **build 161**

- added piglet plugin test harness
- added piglet_scripts with codec and inspector examples
- added doc/dev_guide.sh
- added dev_notes.txt in each src/ subdir
- scrubbed headers

## 15/07/06 - **build 160 - Alpha 2**

- fixed duplicate patterns in file_magic.lua
- warn about rules with no fast pattern
- warn if file rule has no file_data fp
- run fast patterns according to packet type
- update / expand shutdown output for detection
- binder sets service from inspector if not set
- allow abbreviated rule headers
- fix cmake build on linux w/o asciidoc
- add bugs list to manual
- fix memory leaks
- fix valgrind issues
- fix xcode analyzer issues

## 15/07/02 - **build 159**

- added file processing to new_http_inspect
- ported sip preprocessor
- refactoring port group init and start up output
- standardize / generalize fp buffers
- add log_hext.width
- tweak style guide
- fix hosts table parsing

## 15/06/19 - **build 158**

- nhttp splitter updates
- nhttp handle white space after chunk length
- refactor of fpcreate
- refactor sfportobject into ports/*
- delete flowbits_size, refactor bitop foo
- rename PortList to PortBitSet etc. to avoid confusion
- fix ssl assertion
- cleanup cache config

## 15/06/11 - **build 157**

- port ssl from snort
- fix stream_tcp so call splitter finish only if scan was called
- changed drop rules drop current packet only
- unchanged block rules block all packets on flow
- added reset rules to function as reject
- deleted sdrop and sblock rules; use suppressions instead
- refactored active module
- updated snort2lua

## 15/06/04 - **build 156**

- new_http_inspect switch to bitset for event tracking
- fixed stream tcp handling of paf abort
- fixed stream tcp cleanup on reset
- fixed sequence of flush and flow data cleanup for new http inspect

## 15/05/31 - **build 155**

- update default manuals
- fix autotools build of manual wrt plugins
- file processing fixup
- update usage from blog
- add file magic lua
- xcode analyzer cleanup

## 15/05/28 - **build 154**

- new_http_inspect parsing and event handling updates
- initial port of file capture from Snort
- stream_tcp reassembles payload only
- remove obsolete REG_TEST logging
- refactor encode_format*()
- rewrite alert_csv with default suitable for reg tests and debugging
- dump 20 hex bytes per line instead of 16
- add raw mode hext DAQ and logger; fix dns inspector typo for tcp checks
- document raw hext mode
- cleanup flush flags vs dir
- add alert_csv.separator, delete alert_test
- tweak log config; rename daq/log user to hext
- cleanup logging
- stream_tcp refactoring and cleanup

## 15/05/22 - **build 153**

- new_http_inspect parsing updates
- use buckets for user seglist
- fix u2 to output data only packets
- added DAQs for socket, user, and file in extras
- changed -K to -L (log type)
- added extra DAQ for user and file
- added stream_user for payload processing
- added stream_file for file processing

## 15/05/15 - **build 152**

- fixed config error for inspection of rebuilt packets
- ported smtp inspector from Snort
- static analysis fix for new_http_inspect

## 15/05/08 - **build 151**

- doc tweaks
- new_http_inspect message parsing updates
- misc bug fixes

## 15/04/30 - **build 150**

- fixed xcode static analysis issues
- updated default manuals
- added packet processing section to manual
- additional refactoring and cleanup
- fix http_inspect mpse search
- fixed urg rule option
- change daq.var to daq.vars to support multiple params
   reported by Sancho Panza
- ensure unknown sources are analyzed
- pop and imap inspectors ported

## 15/04/28 - **build 149**

- fixed build issue with extras

## 15/04/28 - **build 148**

- fixed default validation issue reported by Sancho Panza
- refactored snort and snort_config modules
- file id refactoring and cleanup
- added publish-subscribe handling of data events
- added data_log plugin example for pub-sub

## 15/04/23 - **build 147**

- change PT_DATA to IT_PASSIVE; supports named instances, reload, and consumers

## 15/04/16 - **build 146**

- added build of snort_manual.text if w3m is installed
- added default_snort_manual.text w/o w3m
- add Flow pointer to StreamSplitter::finish()

## 15/04/10 - **build 145**

- nhttp clear() and related changes
- abort PAF in current direction only
- added StreamSplitter::finish()
- allow relative flush point of zero
- added Inspector::clear()
- new http refactoring and cleanup
- new http changes - events from splitter
- fix dns assertion; remove unused variables

## 15/03/31 - **build 144**

- reworked autotools generation of api_options.h
- updated default manuals
- ported dns inspector

## 15/03/26 - **build 143**

- ported ssh inspector
- apply service from hosts when inspector already bound to flow
- ensure direction and service are applied to packet regardless of flow state
- enable active for react / reject only if used in configuration
- fixed use of bound ip and tcp policy if not set in hosts
- eliminate dedicated nhttp chunk buffer
- minor nhttp cleanup in StreamSplitter

## 15/03/18 - **build 142**

- fixed host lookup issue
- folded classification.lua and reference.lua into snort_defaults.lua
- apply defaults from parameter tables instead of relying on ctors etc.
- fix static analysis issues reported by xcode
- change policy names with a-b form to a_b for consistency
- make all warnings optional
- fix ip and tcp policy defines
- fix ip and icmp flow client/server ip init
- added logging examples to usage

## 15/03/11 - **build 141**

- added build foo for lzma; refactored configure.ac
- enhancements for checking compatibility of external plugins
- added doc/usage.txt

## 15/02/27 - **build 140**

- uncrustify, see crusty.cfg
- updated documentation on new HTTP inspector, binder, and wizard

## 15/02/26 - **build 139**

- additional http_inspect cleanup
- documented gotcha regarding rule variable definitions in Lua
- sync 297 http xff, swf, and pdf updates

## 15/02/20 - **build 138**

- sync ftp with 297; replace stream event callbacks with FlowData virtuals

## 15/02/12 - **build 137**

- updated manual from blog posts and emails
- normalization refactoring, renaming
- fixed icmp4 encoding
- methods in codec_events and ip_util namespaces are now protected
   Codec methods
- 297 sync of active and codecs

## 15/02/05 - **build 136**

- fix up encoders
- sync stream with 297
- fix encoder check for ip6 extensions
- sync normalizations with 297

## 15/01/29 - **build 135**

- fixed freebsd build error
- fix default hi profile name
- updated default snort manuals

## 15/01/26 - **build 134**

- sync Mpse to 297, add SearchTool
- 297 sync for sfghash, sfxhash, tag, u2spewfoo, profiler and target based
- addition of mime decoding stats and updates to mime detection limits
- snort2lua changed to add bindings for default ports if not explicitly
   configured
- added md5, sha256, and sha512 rule options based on Snort 2.X
   protected_content

## 15/01/20 - **build 133**

- fixes for large file support on 32-bit Linux systems (reported by Y M)
- changed u2 base file name to unified2.log
- updated doc based on tips/tricks blog
- fixed active rule actions (react, reject, rewrite)
- moved http_inspect profile defaults to snort_defaults.lua
- add generalized infractions tracking to new_http_inspect
- updated snort2lua to override default tables (x = { t = v }; x.t.a = 1)
- additional codec refactoring
- added pflog codecs
- fixed stream_size rule option

## 15/01/05 - **build 132**

- added this change log
- initial partial sync with Snort 297 including bug fixes and variable
   renaming
- malloc info output with -v at shutdown (if supported)
- updated source copyrights for 2015 and reformatted license foo for
   consistency

## 14/12/16 - **build 131**

- fix asciidoc formatting and update default manuals
- updates to doc to better explain github builds
- fix default init for new_http_inspect
- fix cmake issues reported by Y M
- add missing g++ dependency to doc reported by Bill Parker
- add general fp re-search solution for fp buffers further restricted
   during rule eval; fixes issue reported by @rmkml
- add missing sanity checks reported by bill parker
- tweak READMEs

## 14/12/11 - **build 130**

- alpha 1 release
