2023-03-22: 3.1.58.0

* actions: restore rtn check in Actions::alert and add to Actions::log
* appid: give precedence to eve detected client over appid when eve_http_client_mapping config is set
* detection: fix queue_limit pegcounter evaluation
* host cache: removed some log to prevent log flooding
* js_norm: initialize normalization context only when script is detected
* loggers: fix pcap flushing
* memory: add shell command to dump heap stats

2023-03-09: 3.1.57.0

* ftp_telnet: updated flushing around subnegotiation parameters
* search_engine: allocate a single shared scratch space
* profiler: add rule time percentage table field

2023-02-22: 3.1.56.0

* appid: add validation for rpcbind universal address
* appid: merge cname pattern matchers with ssl pattern matchers
* configure: fix typo in jemalloc with tcmalloc error message
* copyright: update for year 2023
* doc: update sd_pattern docs after obfuscation changes
* sd_pattern: keep obfuscation blocks per buffer

2023-02-08: 3.1.55.0

* appid: first packet detector creation support in appid detector builder script
* appid: support for IPv4 and IPv6 subnets for First Packet API
* appid: updating lua API to accomodate netbios domain extraction, substring search, and substring index.
* appid: use packet thread's odp context instead of inspector's context for packet processing
* build: fix configure_cmake.sh 'too many arguments' error
* detection: add new pegcount
* main: avoid race conditions when accessing id to tid map
* ssl: refactor ssl client hello parser to be used by appid/ssl inspectors
* stream_tcp: fix passive pickups with missing packets. Thanks to nagmtuc and hedayat for reporting and helping debug the issue.
* wizard: ensure Wizard is refcounted by MagicSplitter to prevent snort crashes due to memory corruption

2023-01-25: 3.1.53.0

* appid: publish tls host set in eve process event handler only when appid discovery is complete
* detection: show search algorithm configured
* file_api: handling filedata in multithreading context
* flow: add stream interface to get parent flow from child flow
* memory: added memusage pegs
* memory: fix unit test build w/o reg test

2023-01-18: 3.1.52.0

* dce_rpc: add errno resets during uuid parsing
* dce_rpc: handling dcerpc over smbv2
* flow: update flow creation to exclude non-syn packets with no payload
* framework: change range check types to int64_t to fix ILP32 bit issues
* main: Fix missing include file that caused build error on some platforms.
* memory: add final epoch to capture stats
* memory: add regression test hooks
* memory: fix init sequence; thanks to amishmm and Xiche for reporting and debugging the problem
* netflow: grab the proto off of the netflow record - not the wire packet
* rna: reset host_tracker type when visibility changes
* stream: fix iss and irs and mid-stream sent post processing
* stream: refactor tcp state machine to handle mid-stream flow and more established cases

2023-01-11: 3.1.51.0

* appid: add support for cip service, client and payload detection
* appid: do not create snmp future flow for udp reversed session
* appid: use packet thread's odp context for future flow creation
* build: error out if both jemalloc and tcmalloc are configured
* build: exclude unused memory related sources
* js_norm: add benchmark tests for PDF parser
* js_norm: decode UTF-16BE to UTF-8 for JS in PDF
* js_norm: delete unused method
* js_norm: tune PDF parser performance
* lua: add Adobe JavaScript related identifiers to snort_defaults
* lua: fix typo in Sensitive Data classifications name
* main: fix const issues causing compile warnings
* memory: delete unnecessary includes
* memory: incorporate overloads into profiler
* memory: refactor jemalloc code and add relevant pegs
* memory: rename manager to overloads to better indicate purpose
* memory: update developer notes
* memory: update stats regardless of state; add unit tests
* memory: use the process total instead of per thread totals to enforce cap
* watchdog: print thread id as well for better identification of unresponsive threads

2022-12-19: 3.1.50.0

* alert_fast: fix initialization of http_inspect cheat codes
* config: ensure table state is reset when starting a new shell
* config: fix talos tweaks for the daq module
* data_bus: improve pub-sub performance
* host_cache: fix initialization from Lua
* pop, imap, smtp: gracefully decline buffer requests when flow data is not present

2022-12-15: 3.1.49.0

* appid: appid_detector_builder.sh addPortPatternService call fixed
* appid: do not reset session data when built-in discovery is not done
* appid: fixed assert condition for odp_ctxt and odp_thread_local_ctxt
* doc: add decompression mention to js_norm reference
* doc: update user/js_norm.txt for PDF in email protocols
* geneve: if daq has the capability, do not bypass geneve tunnel
* ips_options: fix offset related bug in byte_test eval()
* js_norm: add PDF stream processing
* js_norm: add support for email protocols
* js_norm: fix pdf_tokenizer_test on FreeBSD platform
* js_norm: update PDF tokenizer to use glue input streambuf
* stream: ignore PAWS timestamp checks when in no_ack mode
* wizard: remove client_first option

2022-12-01: 3.1.48.0

* appid: added config for logging alpn service mappings
* appid: fixed addition of duplicate entries in app_info_table
* appid: make appid availability independent from TP state
* cmake: add FLEX build macro
* doc: update sensitive data documentation
* doc: update user/js_norm.txt for PDF
* flow: add an event for retry packets
* flow: added an event to allow post processing of new expected flows
* flow: fix deferred trust clear when packet is dropped
* flow, stream: added code to track and event for one-sided TCP sessions and generate an event for established or one-sided flows
* http_inspect: add decompression failure check before normalization
* http_inspect: remove port from xff header
* ips_option: keep cursor intact for a negated content mismatched
* ips_option: keep cursor intact for a negated hash mismatched
* js_norm: implement Enhanced JS Normalization for PDF
* js_norm: use FLEX macro to build parser
* process: watchdog to abort snort when multiple packet thread becomes unresponsive
* smb: handling smb duplicate sessions
* stream: add logic to ensure metaACKs cause flushing

2022-11-17: 3.1.47.0

* appid: add a changed bit for discovery finished
* appid: ntp detection improvements
* appid: service, client and payload detection by lua detectors and third-party when first packet re-inspection is enabled
* doc: add JavaScript Normalization section to user manual
* doc: add js_norm alerts to builtin_stubs.txt
* http_inspect: subdivide dev_notes into topics
* http_inspect: move Enhanced JS Normalizer from NHI to a standalone component
* js_norm: implement standalone Enhanced JavaScript Normalizer
* main: dump packet trace after publishing finalize event since verdict could be modified.
* main: update to improve performance by making packet tracer checks before calling function.
* netflow: implement deferred trust, cleanup
* packet_io: allow ACT_TRUST to be used as a delayed action.
* packet_io: the most strict delayed action takes precedence.
* smtp: do not accumulate cmds across policies and reloads. Avoids memory and performance problem.
* stream: add info about the splitter lifetime to dev_notes
* stream: ignore flushing from meta-ack if sent after FIN
* stream: remove splitter from session before inspectors
* stream: set splitter only on initialized tcp sessions or if midstream sessions are allowed
* wizard: remove inspector's ref counter increments from MagicSplitter

2022-11-04: 3.1.46.0

* appid: check for empty patterns in lua detector api input
* appid: publish client and payload ids set in eve process event handler and ssl lookup api only after appid discovery is complete
* detection: add config option for SSE
* detection: skip a rule variable copy for a single-branched node
* doc: add information about handling multiple detection in SSE
* doc: specified which packages are sent on rejection
* helpers: fix duplicate scratch_handler
* http_inspect: add override to destructor
* http_inspect: move LiteralSearch::setup for http_param to its module
* main: add variables to lua environment
* netflow: if LAST_SWITCHED isn't provided, use packet time
* parser: improve port_object hash function
* ports: align fields of PortObject and PortObject2
* ports: enable checks in debug build only

2022-10-25: 3.1.45.0

* detection: check Pig run number in node state conditions. Fixes crash introduced in 3.1.44.0.

2022-10-20: 3.1.44.0

* appid: return APP_ID_NONE only if hsession is not present for http3
* detection: add stateful signature evaluation
* flow, reputation, protocols: remove reputation information from packet and flow
* http_inspect: inspect multiple MIME attachments per message section
* http_inspect: maximum_pipelined_requests
* http_inspect: MIME partial inspections
* http_inspect: remove rule option timing features
* lua: add sensitive data rules
* reputation: added profiling to the event handlers
* reputation: fix for array indexing error when searching for reputation file entries
* reputation: refactor event generation for matches
* s7commplus: adding wizard support for s7commplus
* utils: add possibility to process keywords as identifiers

2022-10-05: 3.1.43.0

* actions: fix action logging for suppressed events
* appid: handle multistream http protocols(http2,http3) together
* appid: return appid set by eve for http/3 if no hsession is present, but prefer hsession appid over eve
* appid: updating devnotes for first packet API
* detection: refactor set next packet to use the dummy active object when there is no packet
* flow: disable inspection for and HA flow unless the state is setup or inspect
* http2_inspect: std::list - remove indirection from stream list
* http_inspect: allowed and disallowed methods
* reputation, sfrt: refactor reputation to remove global variables

2022-09-22: 3.1.42.0

* appid: custom lua detector api to map ip and port to appids on the first packet
* appid: added a snort config to control client-process mapping
* appid: dppid service detection prioritized over third party detection
* appid: cache support for unprocessed ssl packets
* appid: handle http event for httpx(2,3) traffic
* content: fix retry
* content: fix adjustment of depth/within when offset/distance are negative
* detection: add http3 to http ips buffers
* detection: add option to reduce rtns by port values
* doc: added smtp rule 124:17
* flow: abstract class added to work on stream based connections
* http2_inspect: updated with abstracted httpx(2,3) flags
* http_inspect: abstract inspection of httpx(2,3)
* http_inspect: http_max_header_line and http_max_trailer_line rule options
* http_inspect: rework range rule options
* ips_options: change ips.obfuscate_pii to be true by default
* ips: trace all node evaluations
* memory: fix typo in peg counter help text
* netflow: evaluate all matching netflow rules, not just the first match
* parser: add implicit http3 to http ips options otn
* parser: remove platform dependency from parse_int function
* payload_injector: accomodate httpx(2,3) stream id values
* pub_sub: handle httpx(2,3) traffic
* reputation: use the thread specific reputation data for aux ip event
* rna: handle httpx(2,3) traffic
* stream: export support for creating udp session
* trace: ips variables are dumped as hex
* utils: remove alert for an opening tag in string literals
* wizard: deprecate client_first option

2022-09-07: 3.1.41.0

* appid: send intermediate messages for appid reload commands to the socket
* file_api: corrected the formatting of File Statistics output
* file_id: Update Office Documents rules
* flow: update flow statistics before processing a flow
* framework, rna, pub_sub: make data bus get_packet method a const
* netflow: log even when not all info is present
* sd_pattern: add and improve built-in patterns
* stream: free flow data, if flow is blocked
* stream: use a const packet to populate the flow key
* utils: refactor JS normalizer unit tests

2022-08-25: 3.1.40.0

* appid: activate appid debug object before printing logs from http event handler
* appid: do not clear client version when deleting appid session data
* ChangeLog: change to md format
* daq: Remove duplicate entries from static module list; thanks to raging-loon for reporting the issue
* doc: add section on commit messages to the dev guide
* doc: specify parallelization in make in tutorial; Thanks to nitronarcosis for reporting the issue and suggesting a fix
* ffi: add get_module_version(name, type) for conditional config
* flow: fix deferred trust for trust followed by defer
* gid: upper bound changed to match event_filter and rate_filter implementation limits
* help: enclose --help-config string defaults in single quotes
* helpers: make install_oops_handle and remove_oops_handle so_public, install process.h and sigsafe.h
* http_inspect: add doc for http_num_cookies
* http_inspect: add more identifiers to js_norm lists
* http_inspect: http_num_cookies rule option
* http_inspect: parameters for header alerts
* hyperscan: add warning when deserialization fails that includes error code
* ip_proto: enable match on PDUs
* managers: only publish the reloaded flow event for existing flows with an old policy
* parameter: add int_list
* parameter: simplify multi validation
* reputation: make reputation handle flow setup, reloaded, and packet without flow events
* stream: typo in dev_notes; Thanks to RobinLanglois for the fix
* style: change max line length to 120 including \n
* telnet: use the same splitter as ftp_server
* utils: allow closing tag in external scripts
* vlan: add configurable TPIDs; Thanks to ozkankirik for reporting the issue

2022-08-10: 3.1.39.0

* cmake: add --enable-luajit-static option to enable LuaJit linked statically
* http_inspect: request and response shouldn't be available for pkt_data
* ips_options: remove obfuscate_pii caching in sd_pattern option
* main, managers: remove the reload_module command
* netflow: pass a flag if the initiator and responder were swapped
* parser: remove 138 from builtin GID exceptions
* rna: Added log message for missing 'rna.conf' path
* utils: fix compilation warning [-Wcomma]
* utils: fix JS split to reflect tokens correction and re-normalization
* utils: validate escaped JavaScript identifiers

2022-07-28: 3.1.38.0

* appid: restart inspection for ssl session inside http tunnel
* appid: set persistent flag for sunrpc expected session
* appid: send more packets to third-party for FTP user name extraction
* detection: separate the branch/leaf result to different variables
* http_inspect: remove dependency of JS normalization depth on HTTP depth
* http_inspect: add more explicit js type values to otag type check
* http_inspect: do not stop normalization in case of opening script tag
* http2_inspect: add support for GOAWAY frames
* http2_inspect: add support for PRIORITY frames
* http_inspect: directly call detection
* http2_inspect: interface to http_inspect now uses real reassembled packet
* pub_sub: add definitions for ssl block and block with reset messages
* snort2lua: change the conversion of sensitive data rules
* stream: removed all instances of 'cap_weight' config parameter
* stream: removed macro references for 'cap_weight' config parameter
* utils: add static initialization of norm_names
* utils: continue JS normalization after opening tag seen

2022-07-19: 3.1.37.0

* reputation: print LogMessage in reputation only when in verbose mode
* utils: fix Unicode LS PS handling in JavaScript

2022-07-14: 3.1.36.0

* appid: fix stats cleanup
* dce_smb: fix stats cleanup
* file_api: fix stats cleanup
* http_inspect: do not abort midstream pickups
* normalizer: make normalizer and tcp_normalizer peg counts shared
* stream: fix stats cleanup
* utils: fix arrow functions parsing
* utils: fix parsing of decimal number literals

2022-07-08: 3.1.35.0

* sandbox: must propagate file_id for includer logic

2022-07-07: 3.1.34.0

* build: remove unnecessary type casts
* dce_rpc: set presistent flag for dcerpc pinhole session
* file_id: fix rules_file path resolution
* http2_inspect: consider continuation when checking headers length
* log: add log_value and log_limit overloads with built-in integer types
* utils: make shutdown timing stats more precise;
  Thanks to trevor tao <trevor.tao@arm.com> for the update

2022-06-30: 3.1.33.0

* file_api: implement file type identification over ips engine
* filters: check if a configured gid value is supported by filter's implementation
* framework: update base API version to 14
* ftp_telnet: make active ftp expected session in the correct direction
* http2_inspect: fix unit tests depending on REG_TEST
* http_inspect: implement uniform alerts when splitter aborts
* hyperscan: delete databases upon error
* lua: update sid and rev fields
* main: move trace related code to trace folder
* netflow: fix v5 header time value
* parser: update do_hash() function to work correctly with port variables
* parser: use std::string in ExpandVars
* rna: allow rna to fire an event when a new netflow connection is detected
* rna: use the longest user agent fingerprint among multiple matches
* wizard: update wizard's patterns to follow the proto option

2022-06-16: 3.1.32.0

* appid: config for logging eve process to client mappings
* dce_smb: reduce smb_max_credit range to avoid uint16_t overflow
* detection: remove redundant FIXIT
* ftp_telnet: correct the implementation for check_encrypted and encrypted_data config, handle form-feed as
  non-encrypted traffic
* ftp_telnet: handle all space characters as a seperator between FTP request command and arguments
* http_inspect: add explicit check for HTML script opening tag ending
* http_inspect: remove unneeded header inclusions and improve cleanup before trailers
* ips_options: improve ips_hash and ips_cvs code coverage
* log: Fixed missing include for Clear Linux build
* logger: added reload function to create new files when snort reloads
* main: add null check for scratch handler
* mime: cleanup
* modules: resolve int type mismatch in config options
* netflow: fix build on MacOS
* netflow: implement RNA integration for host/service discovery
* netflow: support memcap reconfiguration upon reload
* openssl: Openssl minimum version is set to 1.1.1
* profiler: fix issue with negative number cast to unsigned for max_depth
* rna: reduce range for ttl, fix cast for df, minor and major options;
  Thanks to liangxwa01 for pointing this out
* stream_tcp: fix splitter abort handling
* stream_tcp: flip the server_side flag in fallback() and assert what it should be
* utils, parser: remove redundant fixits
* utils: remove curly brace parsing from regex literals
* utils: remove redundant checks in regex groups
* wizard: use const reference instead of copying

2022-06-02: 3.1.31.0

* appid: add lock_guard to prevent data race on reload
* appid: do not delete third-party connection when third-party reload is in progress and the context swap is not complete
* dce_rpc: convert tree tracker to shared ptr
* doc: add class track description to user doc
* filters: add correct handling of by_src and by_dst;
  Thanks to Albert O'Balsam for reporting the bug
* host_tracker: rename generic files and classes
* http2_inspect: add alert and infraction for non-Data frame too long
* http_inspect: add Content-Type header validation for Enhanced JS Normalizer
* http_inspect: add field for raw_body
* http_inspect: add handling of binary, octal and big integers to JS Normalizer
* http_inspect: change js processed data tracking
* http_inspect: implement general approach of checking Content-Type header
* hyperscan: reallocate hyperscan scratch space when patterns are reloaded during appid detector reload
* netflow: enforce memcap for session record and template LRU caches
* perf_monitor: fix timestamp for idle processing
* utils: add keyword new support and object tracking
* utils: allow script closing tag in single-line comments

2022-05-19: 3.1.30.0

* build: Update dependent libdaq version to 3.0.7
* doc: update clone link in README;
  Thanks to billchenchina
* doc: user documentation update for obfuscate_pii and --help-module
* framework: add method to get unquoted string from configuration value
* http2_inspect: Templatize variable length integer decoding of integer and string
* http_inspect: add ignoring defined object properties for Enchanced JS normalizer
* http_inspect: avoid sending compressed data to JS normalizer
* http_inspect: check if input available before JavaScript normalization
* mime: set partial_header to null after deletion
* perf_monitor: remove unused flatbuffers support
* piglets: remove unused test harness
* smb: handle file context cleanup
* snort3: remove SMB detection from service_netbios.cc
* stream: refactor flush_queued_segments
* stream_tcp: add null check for get_current_wire_packet() in dce too
* stream_tcp, pop: add sync_on_start method to StreamSplitter
* stream_tcp: provide a context and a wire packet where needed, when calling into reassembly from outside regular
  processing (handle_timeouts)
* utils: add Latin-1 decoding of JavaScript unescape-like functions
* utils: allow regex literals after operator
* utils: fix regex char classes parsing
* utils: turn debug-build assertion into a product-build code
* wizard: fix code style

2022-05-04: 3.1.29.0

* appid: add alpn matchers
* dce_rpc: update address space id in the smb keys
* doc: rule text updates
* flow, network_inspectors, policy_selectors, stream: make address space id 32 bits and add a tenant id to the daq header
* flow, side_channel, utils: fix clang issues
* flow: add inline cppcheck suppressions
* flow: change the padding and bits in the flow key to make it more clear
* http_inspect: install header files, create a virtual base class for http_inspect and http_stream_splitter
* http_inspect: move mime processing outside of file and detect depth
* main: update analyzer command log message to copy the variable arguments before using them for the remote response
* wizard: update glob storage due to shared memory

2022-04-25: 3.1.28.0

* appid: add bytes_in_use and items_in_use peg counts
* appid: ssl service detection for segmented server hello done
* binder: add binder actions to flow reassignment;
  Thanks to Meridoff for the original report of the issue
* bufferlen: add missing relative override
* conf: add cip and s7commplus to the default snort.lua
* content: auto no-case non-alpha patterns
* dce_rpc: Handling only named ioctls for smb
* detection: add missing fast pattern buffer translations
* detection: make CursorActionType generic
* detection: map buffers to services
* detection: rearrange startup rule counts
* detection: remove now obsolete get buf support
* doc: add clarification on default bindings in developer notes and user notes
* events: add action logging to the event
* flow, managers, binder: only publish flow state reloaded event from internal execute
* flow: only select policies when deleting flow data if there is a policy selector
* flow, snort_config: change service back to a pointer and add a method to return a non-volatile pointer for service
* flow: use a flag instead off shared pointer use count for has service check
* framework: make Cursor SO_PUBLIC
* ftp: fix FTP response parsing
* ftp: flush FTP cmds ending in just carriage return
* host_cache: bytes_in_use and items_in_use peg counts
* host_cache: fix unit test broken on some platforms
* inspectors: add / update api buffer lists
* ips: eliminate direct dependence on get_fp_buf of all ibt (by using rule options)
* ips: eliminate PM_TYPE_* to make fast pattern buffers generic
* ips: further limit port group rules
* ips_options: eliminate obsolete RULE_OPTION_TYPE_BUFFER_*
* ips_options: fix cursor action type overrides
* main: check policy exists instead of index when setting network policy by id
* mime: handle MIME header lines split between inspection sections and improve folded header line processing
* mms: add check that BerElement argument isn't null before calling BerReader::read
* mms: adding manual updates for the new service inspector for the IEC61850 MMS protocol
* mms: adding new service inspector for the IEC61850 MMS protocol
* mms_data: make a fast pattern buffer
* mms: moved creation of TpktFlowData inspector ID to process init
* module_manager: fix memory pegs display issue during packet processing, while also correctly computing the memory
  pegs in Analyzer::term
* netflow: framework for netflow V5 and V9 events
* packet_io: add rewrite action logging
* parser: update dev notes
* raw_data: only search pkt_data if no alt buffer or raw_data rules included in group
* service inspectors: update fast pattern access
* sfip: improve warning suppression
* smtp: SMTPData initialization changed from memset to constructor
* smtp: STARTTLS command injection event processing
* stream: add can_set_no_ack() api to check if policy allows no-ack mode
* stream: add current_flows, uni_flows and uni_ip_flows peg counts
* utils: limit JS regex stack size
* utils: track groups and escaped symbols in JavaScript regex literals

2022-04-07: 3.1.27.0

* ac_full: refactor api access
* ac_full: remove cruft
* ac_std: fix case translation buffer size
* alerts: remove obsolete stateful parameter
* appid: provide client appid set by encrypted visibility engine to ssl through the ssl appid lookup api
* build: compile against libatomic if present;
  Thanks to W. Michael Petullo <mike@flyn.org>
* control, shell: add a command to set the network policy to be used by subsequent commands
* dce_rpc: handle cleanup path and race conditions for dce traffic
* detection: do not check ips policy when builtin events are queued
* detection: fixup dump of detection option tree
* detection: minor refactoring of rule header access
* detection: override match queue limit for offload
* detection: remove cruft
* detection: skip match deduplication for hyperscan
* file_api: handle user_file_data cleanup
* hext: change stdin designation from tty to - since the trough uses dash
* http2_inspect: reduce holes in objects
* http_inspect: add unescape text processing for Enhanced JS Normalizer
* http_inspect: decode String.fromCodePoint() JavaScript function
* http_inspect: delete alerts 119:279 and 119:280
* http_inspect: provide current packet to trace
* http_inspect: support headers Restrict-Access-To-Tenants, Restrict-Access-Context
* hyperscan: ensure adequate scratch when deserializing
* rate_filter: move to inspection policy
* search_engine: add fast pattern only count at startup
* search_engine: always build ac_full since it is a hard default case
* search_engine: fix .debug = true output
* search_engine: fix adjustment for fast_pattern_offset
* search_engine: fix fast pattern only eligibility check
* search_engine: remove obsolete warning on max_pattern_len change
* search_engine: remove search_optimize parameter (always true)
* search_engine: truncated patterns not eligible as fast pattern only contents
* search_engines: add and refactor unit tests
* search_engines: ensure SearchTool with hyperscan gets multi-match mode
* search_engines: remove the legacy ac_banded algorithm
* search_engines: remove the legacy ac_sparse algorithm
* search_engines: remove the legacy ac_sparse_bands algorithm
* search_engines: remove the legacy ac_std algorithm
* sfip: suppress compiler warning
* utils: add string concatenation for Enchanced JS Normalizer
* utils: allow opening/closing tags in external scripts
* utils: fix JS Normalizer benchmark build
* utils: fix tracking variable when the output buffer is reset
* utils: harden script opening tag sequence

2022-03-23: 3.1.26.0

* actions: revert bf62a22d43bb2d15b7425c5ec3e3118ead470e8d
* actions: set a delayed action on Reject IPS Action hit
* analyzer: avoid distilling sticky verdicts
* appid: appid api to provide the path to appid detector directory
* appid: make appid a global inspector
* appid: sum stats at tterm and null the thread local stats pointer after delete
* control: make sure reload commands with empty argument is handled correctly
* event: add new static member update_and_get_event_id()
* file_api: Handling user_file_data cleanup
* flow: make service a shared pointer to handle reload properly
* framework: update base API version to 13
* http_inspect: do file decompression and utf decoding on non-MIME uploads
* http_inspect, mime: VBA macro decompression for HTTP MIME file uploads
* inspector, main, inspector_manager: add support for thread local data in inspectors and commands updating reload_id
* main: add the control connection to the analyzer command and a method to log a message to both console and the remote
  connection
* main: fix and reenable the distill_verdict unit test
* managers: add a faster get_inspectors method
* managers: add get_inspector unit tests
* managers: move inspection policies into the corresponding network policy
* packet_io: fix active action so the first reset occurred takes effect
* policy_selectors: add a method to select policies based on DAQ_FlowStats_t
* reputation: add a command to reload repuation data
* stream: reusable stream splitter

2022-03-09: 3.1.25.0

* appid: do not add duplicate process to client app mapping for the same process name
* file_id: remove unused decompression and decode depth parameters
* http_inspect: add http_header_test, http_trailer_test rule options
* http_inspect: add override to fix warning
* http_inspect: add unescape function tracking for Enhanced JS Normalizer
* http_inspect: call mime in a loop for each attachment
* http_inspect: remove feature to disable raw detection upon flow depth
* http_inspect: use http_inspect decompression config parameters for HTTP MIME traffic instead of file_id
* mime: fix resetting state after every attachment and check state instead of decode object
* mime: return at the end of each attachment and set the file_data for http
* process: add watchdog to detect packet threads dead lock or dead loop
* ssh: NULL check for session pointer before access
* stream_tcp: call final flush only when the seglist has no gaps
* stream_tcp: clarify small segments help text and remove usage from lua
* utils: check for NULL before calling fclose()
* utils: check more likely branches at first
* utils: combine ignore list with normalization map
* utils: fix compilation issues in js_tokenizer
* utils: improve Flex matching patterns
* utils: pre-compute ID normalized names
* utils: refactor the alias lookup
* utils: wrap unordered set with a fast lookup table
* watchdog: remove unused code

2022-02-23: 3.1.24.0

* detection_filter: update dev notes to show multithreaded behavior
* doc: fix typos in text;
  Thanks to Greg Myers <myersg86> for reporting the issue
* http_inspect: refactor HttpIpsOption
* latency: disabling time out functionality on implicit enable
* mime: stop setting the file_data buffer for raw non-file MIME parts
* netflow: add dev_notes.txt
* sfdaq: fix for underflow of outstanding counter
* stream: Remove preemptive prunes peg count

2022-02-09: 3.1.23.0

* detection: add dir abort check in skip_raw_tcp
* doc: add notes about CLI/Lua precedence
* doc: fix incorrect http builtin rule sid
* event: make apis SO_PUBLIC to access in .so
* filters: allow detection filter to sum events across threads
* http_inspect: HttpStreamSplitter::reassemble verifies gzip file magic and checks for FEXTRA flag
* main: ignore Snort module's option if it duplicates CLI option
* main: parse snort module before others
* main: remove default values for other-module parameters in snort module
* main: stop with error on include(nil) attempt
* packet_io: decrease daq module's parameters priority
* stream: defer flush_queued_segments() if flow->clouseau
* stream_tcp: better place for setting delayed_finish_flag
* stream_tcp: fix a bug in which in some cases we did not call splitter finish() in each direction, by calling
  flush_queued_segments() in perform_fin_recv_flush() on FIN with data packets
* stream_tcp: introduce TcpStreamTracker::delayed_finish_flag and call splitter finish from flush_on_data_policy
  if delayed_finish_flag is true
* stream_tcp: wrap flow->clouseau in searching_for_service()

2022-01-31: 3.1.22.0

* appid: give priority to custom process to app mappings over ODP mappings
* appid: rename efp (encrypted fingerprint) to eve (encrypted visibility engine)
* detection: change output format of dump-rule-state
* pub_sub: export assistant_gadget_event.h header file
* stream: set the max number of flows pruned while idle to 400

2022-01-25: 3.1.21.0

* appid: do not delay detection of SMB service for the sake of version detection
* control: fix macro definitions
* copyright: Update year to 2022
* http_inspect: correct comment regarding header splitting rules
* http_inspect: forward 0.9 request lines to detection
* http_inspect: http_version_match uses msg section version id
* http_inspect: webroot traversal
* main: move policy selector and flow tracking from snort config to policy map
* main: only add policies to the user policy map at the end of table processing
* policy: add a file_policy to the network policy and use it
* stream: QUIC stream dependent changes
* stream_tcp: ensure that we call splitter finish() only once per flow, per direction
* wizard: remove extra semicolon

2022-01-12: 3.1.20.0

* appid: handle SNI in efp event
* appid: make peg counts consistent with what is reported to external components
* appid: update appid api to include ssh in the list of service inspectors that need inspection
* dnp3, gtp, file_type: fix assert while parsing string param
* doc: update JavaScript normalization docs
* http2_inspect: don't send data frames to the http stream splitter when it's not expecting them
* http2_inspect: hardening
* http_inspect: version update, http_version_match rule option
* stream_tcp: limit reassembly size for AtomSplitter;
  Thanks to barosch78 and DAKOIT for their help in the process of finding the root cause
* stream_tcp: Skip seglist gap in post-ack mode if data is acked beyond the gap
* stream_user: change packet type from PDU to USER for hext daq, user codec, and stream_user
* wizard: make max_search_depth applicably for curses

2021-12-15: 3.1.19.0

* appid,ssh: roll AppId's SSH detector into SSH service inspector
* appid: remove hard-coded SSH client patterns which are available as part of ODP
* build: add cppcheck suppressions for unusedFunctions
* build: clean up some cppcheck style issues
* build: move flex options to the template file
* cmake: fix CMP0115 Warning
* daq: sort --daq-list output by module name
* dce_smb: add new smb counters
* file_api: add null check for user file data
* file_api: handle file_data
* framework,appid: generate NO_SERVICE event when no inspector can be attached to a flow; wait for the event in appid
  before declaring service as unknown for the flow
* http_inspect,http2_inspect: refuse midstream pickups
* http_inspect: add JavaScript builtin de-aliasing
* http_inspect: rename js normalization options
* http_inspect: use correct detect_length for partial inspection cleanup
* loggers: fix truncated alert_syslog messages
* lua: configure a list of JS ignored IDs in default_http_inspect table
* managers: continue inspectors probe when packet has disable_inspect flag
* mime: add the support for vba macro data extraction of  MS office files transferred over mime protocols
* parser: fix missing-prototypes warning in parse_ports.cc
* parser: fix parsing of portsets
* rpc: remove RpcSplitter altogether and use LogSplitter instead
* snort2lua: fix conversion of variable sets
* stream: add PKT_MORE_TO_FLUSH flag and use it in TcpReassembler::scan_data_post_ack() to signal AtomSplitter whether
  to flush or not
* stream: fix issue with atom splitter not returning FLUSH
* stream_tcp: remove unnecessary special adjustment methods
* utils: (JSTokenizer) fix braces initialization compilation error (gcc5)
* utils: fix state adjustment in JS Tokenizer
* utils: place init/deinit routine under a single function
* utils: update JS normalizer unit tests
* vlan: implement vlan encode function

2021-12-01: 3.1.18.0

* alert_sf_socket: remove obselete logger
* appid: exclude stubs from coverage
* build: remove config.h from headers
* build: remove unreachable code
* build: update configure options
* catch: update catch to v2.13.7
* dev_notes.txt: fix miscellaneous typos
* doc: remove mention of Automake
* doc: update builtin_subs.txt with EVENT_JS_SCOPE_NEST_OVERFLOW alert
* doc: update module usage and inspector types in the dev guide
* doc: update user/http_inspect.txt with http_inspect.js_norm_max_scope_depth option description
* doc: update wizard documentation
* file_api: file_data changes
* framework: add support for multiple tenant
* framework: don't call a gadget's eval() or clear() after its stream splitter aborted
* framework: replace Value::get_long() with a platform-independent type
* framework: update base API version to 11
* helpers: fix stream unit test on 32 bit platforms
* http2_inspect: discard with padding
* http_inspect: fix total_bytes peg count
* http_inspect: new rule options num_headers, num_trailers
* http_inspect: store ole data in msg_body
* http_inspect: update comments for asserts in eval and clear
* http_inspect: update dev_notes.txt
* hyperscan: disable bogus unit test leak warnings
* ips_options: create LiteralSearch object for vba decompression at the time of snort initialization
* memory: add max rss to verbose memory output
* memory: add original overload manager
* memory: add support for jemalloc
* memory: expand profile report field widths
* memory: fix accounting issues
* memory: free space per DAQ message, not per allocation
* memory: move mem_stats to MemoryCap
* memory: refactoring
* memory: refactor pruning and update unit tests
* memory: remove explicit allocation tracking
* memory: update dev notes
* perf_monitor: allow constraint seconds = 0
* piglets: refactor support code
* reputation: remove unused sfrt code
* rna: refactor unit test stubs
* search_engines: remove unused test code
* stream_tcp: delete unused unit test cruft
* stream_tcp: only fallback if stream splitter aborted and don't keep processing fragments after MagicSplitter returned
  STOP
* stream_tcp: remove unused unit test code
* stream_user: refactor, remove cruft
* unified2: remove cruft
* utils: do output adjustment in case of carryover
* utils: enable batch mode for Flex
* utils: (JSNormalizer) add program scope tracking and alias resolution
* utils: (JSNormalizer) rework the split over multiple chunks behavior
* utils: pass an address into memset instead of object
* utils: reduce flex generation of unused js normalizer code
* utils: reset Normalizer context when new script starts
* vba: fix buffer overflow in ole parser
* wizard: add patterns to match unknown HTTP and SIP methods
* wizard: change default value of max_search_depth from 64 to 8192
* wizard: remove telnet IAC pattern

2021-11-17: 3.1.17.0

* appid: restore the log of reload detectors complete message
* build: remove HAVE_HYPERSCAN conditional from installed header
* detection: add allow_missing_so_rules
* detection: ensure PDUs indicate parent when available
* dnp3: update builtin rule description
* doc: arp_spoof builtins
* doc: back orifice builtin rules
* doc: spell correction
* doc: update builtin alerts description for dnp3
* doc: update builtin alerts description for modbus, HTTP/2
* doc: update builtin alerts description for portscan
* doc: update builtin rule documentation for http_inspect
* doc: update builtin rules documentation for dce_smb, dce_tcp, dce_udp, rpc_decode
* doc: updated builtin rules documentation for ssh
* http2_inspect: hardening
* http2_inspect: http1_header buffer always created immediately after decode_headers
* http2_inspect: push promise error state check
* http2_inspect: truncated trailers without frame data
* ips_option: Enabling trace for vba_data options and fixing memory leak while extracting vba_data
* main: use dynamic buffer on demand in trace print functions
* u2spewfoo: Fixed incorrect usage line

2021-11-03: 3.1.16.0

* appid: during initialization, skip loading of Lua detectors that don't have validate function
* appid: in packet threads, skip loading of detectors that don't have validate function on reload
* appid: provide API to give client_app_detection_type
* codec: geneve - ensure injected packets have geneve port in outer udp header
* detection: refactor mpse serialization
* detection: rename PortGroup to the more apt RuleGroup (and related)
* detection: replace PortGroup::alloc/free with ctor/dtor
* doc: add SIP built-in rule documentation
* doc: update built-in rule doc for SMTP, IMAP and POP inspectors
* doc: update built-in rules documentation for dns module
* doc: update built-in rules documentation for ftp-telnet
* doc: updated builtin rules documentation for gtp module
* flow: fix warning in flow_cache.cc
* flow: use the same pkt_type to link and unlink unidirectional flows
* http2_inspect: refactor decoded_headers_buffer for hpack decoding
* http_inspect: eliminate cumulative js data processing
* http_inspect: handle unordered PDUs for inline/external JavaScript normalization
* http_inspect: improve file decompression
* hyperscan: sort patterns for dump / load stability
* ips: correct fast pattern port group counts
* mpse: add md5 check to deserialization
* reload: add logs to track reload process
* reload: move out reload progress flag to reload tracker
* search_engine: support hyperscan serialization
* search_engine: support port group serialization
* sip: track memory for sip sessions
* ssl: disable inspection on alert only at fatal level
* stream_tcp: fix init_wscale() to take into account the DECODE_TCP_WS flag
* tcp: remove the obsolete __GNUC__ block from TcpOption::next()
* tcp: stop on the EOL option in TcpOptIteratorIter::operator++()
* utils: add get methods to peek in internal buffer
* utils: correct Normalizer's output upon the next scan
* wizard: update globbing and max_pattern

2021-10-21: 3.1.15.0

* appid: detect client based on longest matching user agent pattern
* appid: update the name of the lua API function that adds process name to client app mappings
* build: fix in CodeCoverage.cmake to generate *.gcda *.o files as needed by gcov
* dce_smb: optimize handling pruning of flows in stress environment
* decompress, http_inspect: add support for processing ole files and for vba_data ips option
* doc: add punctuation to builtin stubs, fix formatting
* doc: builtin rule documentation updates
* http2_inspect: partial header with priority flag set
* http_inspect: add automatic semicolon insertion
* http_inspect: document built-in alerts
* http_inspect: do not normalize JavaScript built-in identifiers
* http_inspect: hardening
* http_inspect: implement JIT (just-in-time) for JavaScript normalization
* http_inspect, ips_option: decouple the vba_data ips option from http_inspect and add the trace debug option to vba_data
* policy: update policy clone code to avoid corrupting active configuration
* protocols: prevent infinite loop over tcp options
* rna: call set_smb_fp_processor function in reload tuner
* rna: do not do service discovery for future flows

2021-10-07: 3.1.14.0

* appid: enhance RPC service detector to handle RPC Bind version 3
* appid: fix update_allocations signature in unit test
* appid: log appid daq trace first followed by subscriber modules
* appid: provide api for Lua detectors to map process name to client app
* doc: add descriptions for 119:265-271 builtin alerts
* doc: update builtin stub rule reference strings
* file: add file policy id and other config data as part of packet tracer command under File phase
* file_api: add decompress_buffer_size
* flow: add total flow latency to flowstats
* http2_inspect: compare scanned bytes to total received during reassemble
* http2_inspect: protect against reassemble with more than MAX_OCTETS
* http_inspect: change format of normalized JS identifiers
* ips_options: rename script_data buffer to js_data
* latency: add configuration for implicit enable
* lua: fix Talos tweak snaplen
* rna: support CPE new os RNA event
* snort_config: adding api for enabling latency module
* utils: add custom i/o stream buffers to JS normalizer
* utils: adjust output streambuffer expanding strategy and reserved memory
* utils: fix compilation error of js_identifier_ctx_test for clang

2021-09-22: 3.1.13.0

* appid: prioritize appid's client detection over third-party
* appid: stay in success state after RPC is detected
* builtins: add --dump-builtin-options
* catch: enable benchmarking
* cip, iec104: update stub rule messages for consistent format
* control: explicitly include ctime header in control.h
* detection: add fast patterns only once per service group
* doc: add support for details on builtin rules in the reference
* doc: update reference for 2:1 and 129:13
* doc: update the documentation of "replace" option and "rewrite" action
* doc: update user tutorial with '--enable-benchmark-tests' option
* file_api: new api added for url
* file_api: revert store processing flow in context
* flow: don't do memcap pruning if pruning is in progress
* host_cache: Avoid data race in cache size access
* host_tracker: Removing unused methods
* http_inspect: http_raw_trailer fast pattern
* http_inspect: pass file_api the uri with the filename and extract the filename from the uri path
* http_inspect: remove memrchr for portability
* netflow: use device ip and template id to ensure that the template cache keys are unique
* output: adopt the orphaned tag alert (2:1)
* rna: Avoid data races in vlan and mac address
* rna: Avoid infinite loop in ICMPv6 options
* smb: added a null check when current_flow is not present
* snort2lua: Fixed version output (issue #213);
  Thanks to A-Pisani for the fix
* stream: change session_timeout default for tcp, ip, icmp and user
* stream: fix session timeout of expired flows
* trough: Avoid data race in file count
* utils: add benchmark tests for JSNormalizer
* utils: add reference and description for ClamAV test cases
* utils: avoid using pubsetbuf which is STL implementation dependent
* utils: fix typo in js_normalizer_test

2021-09-08: 3.1.12.0

* decoder: icmp6 - use source and destination addresses from packet to compute icmp6 checksum when NAT is in effect
* http_inspect: enable traces for JS Normalizer
* http_inspect: include cookies in http_raw_header
* http_inspect: reduce void space in HttpFlowData
* stream_tcp: add pegs for maximum observed queue size
* stream_tcp: normalize data when queue limits are enabled
* stream_tcp: only update window on right edge acks
* stream_tcp: set sequence number in trimmed packets up to the queue limit and increase defaults

2021-08-26: 3.1.11.0

* build: update help for --enable-tsc-clock to include arm;
  Thanks to liangxwa01 for reporting the issue
* codec: geneve: fix incorrect parsing of option header length
* data_bus: support ordered call of handlers
* dns, ssh: remove obsolete stream insert checks
* doc: Add js_norm_max_template_nesting description
* flow: introduce bidirectional flag for expected session
* flow: set the client initiated flag before publishing the flow state setup event
* framework: update base API version to 8
* framework: version rollback
* http_inspect: add builtin rule for consecutive commas in accept-encoding header
* http_inspect: Add JavaScript template literals normalization
* http_inspect: check if Normalizer has consumed input
* http_inspect: hard-code infraction enum numbers
* http_inspect: http_raw_header, http_raw_trailer field support
* http_inspect: refactor NormalizedHeader
* http_inspect: support more infractions and events
* http_inspect: two new built-in rules
* inspection: process wizard matches on defragged packets
* ips: add action_map table to map rule types, eg block -> alert
* ips: add action_override which applies to all rules
* lua: update comments in the default config
* modbus: check record length for write file record command
* normalize: remove tcp.trim config
* payload_injector: check if stream is established on flow rather than the packet flag to handle retries
* policy: put inspection policy accessors in public space
* policy: reorganize for sanity
* README: mention vars in default config
* sip: deprecate max_requestName_len in favor of max_request_name_len
* smb: Invoke SMB debug in destructor when packet thread available
* stream_tcp: update API called by payload_injector to check for unflushed queued TCP segments
* style: remove crufty comments
* style: remove C style (void) arglists
* style: remove or update crufty preprocessor comments
* utils: address compiler warning
* utils: support streamed processing of JS text
* wizard: support more HTTP and SIP methods

2021-08-11: 3.1.10.0

* appid: update netbios-ss (SMB) detector to extract SMB domain from SMBv2, and more intelligently handle payload
  appid detection
* appid: use packet thread odp context while creating SIP session
* build: install DAQ modules and Snort plugins in separate folders
* dce_smb: restore file tracker size post deletion
* dns: add DNS splitter
* doc: update user manual for identifier normalization
* file_api: add infra and file debugs to existing debugging framework
* ftp: remove unused defines and crufty comments
* http_inspect: add JavaScript identifiers normalization
* http_inspect: change the default value of request_body_app_detection config parameter to true
* smtp: remove unused defines
* ssh: handle traffic with invalid version string
* ssh: handle version string packets that also contain key exchange data
* stream_tcp: skip unordered segments if last flushed position already moved past
* telnet: correct help for ayt_attack_thresh
* wizard: add wizard max_pattern option and update HTTP/SIP aware methods patterns

2021-07-28: 3.1.9.0

* actions: allow session data to stay accessible for loggers for reject rule action
* byte_options: address compiler warnings
* control: add idle expire removal to control channels
* dump_stats: direct output back to command channel
* events: use instance_id to make event_id unique across threads
* file_api: handle file_cache inspection for non-zero offset
* http2_inspect: change xor to or in assert that was failing due to uninitialized variable
* http2_inspect: fix HPACK dynamic table size update management
* http2_inspect: remove unused variables
* http_inspect: add peg count for script bytes processed
* http_inspect: add rule option http_raw_header_complete
* http_inspect: don't allocate 0-length partial inspection buffer
* ips_options: add catch tests for byte_test, byte_jump, byte_math, byte_extract
* ips_options: address compiler warnings
* ips_options: refactor byte_extract, byte_test, byte_math, byte_jump and related tests
* lua: update HTTP/2 default_wizard hex with S2C pattern match
* stats: update file and appid stats to use Log functions provided from stats.cc

2021-07-15: 3.1.8.0

* appid: support SSH client detection through lua detector
* dce_rpc: fix crash when expected session comes after snort reload
* dce_rpc: handling raw packets
* dce_smb: added trace messages and multiple level logging for SMB module
* dce_smb: fixed macro definition for SMB_DEBUG
* doc: fix build warnings;
  Thanks to jiangrj (github.com/jiangrij) for reporting the issue
* dump_config: support modules without config options in text format
* file_api: handling overlap segments
* http2_inspect: clean data cutter internal state after exhausting flow depth
* http_inspect: add built-in alert for script tags in a short form
* packet_io: check if unreachable_candidate before sending unreachable
* packet_io: unreachable packets shouldn't be sent for ICMP
* snort2lua: set raw_data buffer for rawbytes and B flag in PCRE
* wizard: make SSH spell more specific

2021-06-30: 3.1.7.0

* appid: enhance netbios service detector to identify SMB versions as web app
* appid: update documentation
* appid: update the DNS detector to support the all record request
* control: resolve socket issues due to race conditions
* doc: updates for http2_inspect
* framework: update base API version to 3
* main: implement test_features run flag to enable debug-like output
* mime: track memory for mime sessions
* payload_injector: don't inject if there are unflushed S2C TCP packets queued
* reputation: include list id for daq trace log
* sfip: fix unit tests for non-regtest builds
* snort2lua: fix lua conversion of unsupported http preproc options without parameters
* snort2lua: remove footprint size config
* stream: fix is_ack_valid to return true even when current ack is to the left of snd_una, per RFC793

2021-06-16: 3.1.6.0

* appid: extract auxiliary ip when uri is provided by third-party
* appid: perform detection on request body for HTTP2 traffic
* appid: remove error message when userappid.conf is not present
* appid: remove unused metadata offset functionality
* appid: support fragmented metadata
* appid: use 32 bits for storing protocol field in RPC port map message
* codecs: geneve - add support for Geneve encapsulation
* codecs: geneve - add vni to alert_csv and alert_json
* codecs: support inner flow NAT
* control: allow compile with shell disabled
* control: clean up cppcheck issues
* control: expose ContrlConn API
* control: refactor control channel management to better handle control responses
* control: remove SHELL compile flag from header
* control: remove unused IdleProcessing functionality
* dce_rpc: SMB multichannel - add smb multichannel file support
* dce_rpc: SMB multichannel - handle negotiate command to create expected flow
* dce_rpc: SMB multichannel - introduce locks
* dce_rpc: SMB multichannel - make session cache global
* dce_rpc: SMB multichannel - own memory tracking in global cache
* dce_rpc: fix warnings
* dce_rpc: handle reload prune for smb session cache
* dce_rpc: store shared pointer of session tracker
* doc: update JS normalizer options
* file_api: increase file count only once per file
* file_api: store processing flow in context
* filters: change rate filter to use network policy id instead of ips policy id
* filters: support rate filter to work with PDUs
* flow: enable support for multiple expected sessions
* ftp: create additional expected session if negotiated IP is different from server IP on packet
* gtp : check protocol type according to gtp version
* host_cache: remove unused lua mock code from the tests
* http2_inspect: don't perform valid sequence check on rst_stream frame
* http2_inspect: improve request line generation and checks
* http2_inspect: rule options and doc clean up
* http2_inspect: track dynamic table memory allocation
* http_inspect: add JS Normalizer to dev_notes
* http_inspect: add JS normalization for external scripts
* http_inspect: additional memory tracking
* http_inspect: extend built-in alerts for Javascript processing
* http_inspect: improve MPSE in HttpJsNorm (script start conditions)
* http_inspect: limit section size target for file processing
* http_inspect: publish event for http/2 request bodies
* http_inspect: support partial detect for Javascripts
* http_inspect: track memory footprint of zlib inflation
* http_inspect: update test mock api
* iec104: delete trailing spaces
* ips_options: fix intrusion alerts generation for tcp rpc PORTMAP traffic when rpc_decode is bound to the flow
* main: add support for resuming particular thread
* main: fix config dump for list-based inspector aliases
* mime: store extra data in stash
* packet_io: enable expected session flags
* protocols: remove inline specifiers for functions defined within a structure declaration
* pub_sub: add get_uri_host() to HttpEvent
* pub_sub: update HttpEvent::get_host to get_authority - now always includes port if there is one
* reputation: daq trace log
* reputation: support auxiliary IP matching upon reload
* rna: filter DHCP events and some refactoring
* rna: update last seen time on deleted host rediscovery
* stream: enable support for multiple expected sessions
* stream_tcp: populate flow contents in context for non-wire packets
* time: make Periodic class SO_PUBLIC
* trace: place trace options under the DEBUG_MSGS macro
* utils: fix warning about empty statement
* utils: refactor JSTokenizer
* utils: rework JSNormalizer class

2021-05-20: 3.1.5.0

* appid: Publish an event when appid debug command is issued
* appid: do memory accounting of api stash object, dns/tls/third-party sessions
* appid: mark payload detection as done after either http request or response is inspected
* appid: set monitor flags on future flows
* dce_rpc: fix expected session protocol id
* dce_rpc: update memory tracking for smb session data
* dce_rpc: use find_else_insert in smb session cache to avoid deadlock
* file_api: fix spell source error
* flow: Adding stash API to save auxiliary IP
* flow: Enhancing APIs to stash auxiliary IP
* flow: memory tracking updates
* hash: add new insert method in lru_cache_shared
* http2_inspect: add assert in clear
* http2_inspect: concurrent streams limit is configurable
* http2_inspect: fix non-standard c++
* http2_inspect: handle trailer after reaching flow depth
* http2_inspect: implement window_update frame
* http2_inspect: optimize processing after reaching flow depth
* http2_inspect: track stream memory incrementally instead of all up front
* http2_inspect: update discard print
* http2_inspect: update state and delete streams after reaching flow depth
* http_inspect: IP reputation support
* http_inspect: don't disable detection for flow if it's an HTTP/2 flow
* ips_options: fix relative base64_decode
* memory: free_space cleanup
* netflow: additional check before v5/v9 decode
* netflow: version 9 decoding and filtering
* packet_tracer: IPS daq trace log
* packet_tracer: file daq trace log
* parser: Remove rule merge in dump mode
* parser: reduce RTNs only after states applied
* reputation: track monitor ID via flow; minor code cleanup
* shell: exit gracefully when sanbox lua is misconfigured
* stream_tcp: Deleting session when both talker and listener are closed
* stream_tcp: Using window base for reset validation

2021-04-21: 3.1.4.0

* appid: (fix style) Local variable 'version' shadows outer variable
* appid: Delete third-party connections with context only if third-party reload is not in progress
* appid: clean up lua stack on C->lua function exit
* appid: clean-up parameters in service_bootp
* appid: detect payload based on dns host
* appid: in continue state for ftp traffic, do not change service to unknown on validation failure
* appid: monitor only the networks specified in rna configuration
* appid: refactor to set http scan flags in one place
* appid: remove detectors which are available in odp
* appid: remove duplicate rtmp code
* binder: update flow data inspector on a service change
* build: add better support for flex lexer;
  Thanks to Özkan KIRIK and Moin for reporting the issue
* codecs: use held packet SYN in Tcp header creation
* copyright: Update year to 2021
* dce_rpc: Added a cleanup condition for DCERPC in close request
* dce_rpc: DCERPC Support over SMBv2
* dce_rpc: Fixed prototype mismatch. Smb2Tid doesn't need to be inline
* doc: add documentation for script_data ips option
* doc: revert documentation related to script_data ips option
* framework: Adding IT_FIRST inspector type to analyze the first packet of a flow
* hash: prepond object creation in LRU cache find_else_create
* host_tracker: fix bug in set_visibility
* http2_inspect: fix possible read-after-free in hpack decoder
* http2_inspect: free streams in completed/error state
* http_inspect: fix end of script match after reload
* http_inspect: remove detained inspection config
* ips: allow null detection trees with negated lists
* ips_options: add sticky buffer script_data ips option within normalized javascripts payload
* main: Adding reload id to track config/module/policy reloads
* main: Log holding verdict only if packet was actually held
* main: Update memcap for detained packets
* netflow: add device list configuration
* netflow: add filter matching for v5 decoder
* netflow: get correct zone info from packet
* packet_io: If packet has no daq_instance, use thread-local daq_instance
* packet_tracer: Appid daq trace log
* packet_tracer: fix trace condition for setting IP_PROTO
* payload_injector: send go away frame
* pcre: revert change that disabled jit
* reputation: Registering inspector to the IT_FIRST type
* rna: add the smb fingerprint processor to the get_or_create / set processor api
* ssl: refactoring SSLData out so it can be reused
* stream: Add held packet to retry queue when requested
* stream: Add partial_flush. Flush one side of flow immediately
* stream: IP frag packets won't have a flow so do not try to hold them
* stream: fetch held packet SYN
* stream: fix race condition in HPQReloadTuner
* stream: store held packet SYN
* utils: enable Flex C++ mode via its option

2021-03-27: 3.1.3.0

* actions: Dynamically construct the default eval order for all the loaded IPS actions
* actions: Make all IPS actions pluggable
* appid: Make netbios domain available through appid API
* appid: SMB fingerprinting support
* cmake: Add flex build dependency
* dce_rpc: Refactor SMB code
* detection: Update detection.alert, to be used instead of reputation.total_alerts
* detection: Update dump_rule_meta function to only print rules from default IPS policy
* detection: Update the rtn's listHead to reflect the new action set in the rule state
* doc: Update http_inspect feature documentation
* flow: Add packet tracer output to DAQ expected flow requests
* host_tracker: Fully populate local hostclient before logging
* http2_inspect: Alert on uppercase header name encoded in HPACK
* http_inspect: Add JavaScript whitespace normalization
* http_inspect: Add normalization_depth config option
* http_inspect: Alert on HTTP/2 upgrade attempts
* http_inspect: Integrate JSNormalizer (whitespace normalization) keeping the old one
* packet_io: Update for the removal of the RETRY DAQ verdict
* packet_tracer: Do not log non-IP packets when enabled from shell and a constraint is set
* parser: Support duped RTN if its header has been changed
* rate_filter: Get the available IPS actions dynamically to configure the new_action
* rna: Make discovery filter use client and server interfaces if they are not unknown
* rna: SMB fingerprinting support
* snort2lua: Delete conversion of disable_replace option
* snort2lua: Fix lua conversion of http preproc options
* snort: Add -h to output the help overview (same as --help)
* snort_config: Remove is_active_enabled and set_active_enabled functions
* style: Change C++ comment NULL to null
* style: Remove unnecessary cruft
* style: Remove unused cruft
* utils: Add JSNormalizer

2021-03-11: 3.1.2.0

* action_manager: Remove unused cached reject action
* appid: Always get appid inspector from default inspection policy
* appid: Fixes for cppcheck warnings
* appid: Get uri from http event even when http host is not present
* appid: Load lua detectors for packet threads from compiled lua bytecode during detector reload
* appid: Remove app forecast method
* appid: Remove detectors for obsolete apps - AOL instant messenger and Yahoo messenger
* appid: Send reloading detectors message to socket immediately
* appid: Update IMAP service detector pattern
* appid: Use opportunistic tls event to set decryption countdown for SMTP detector
* binder: Apply host attribute table information at the beginning of flow setup
* binder: Clean up std namespace usage
* binder: Use service inspector caching to improve get_gadget() performance
* binder: Use the first match for non-terminal binding usage
* build: Do one more pass of modernizing the C++ code
* dce_rpc: Handle async responses in smbv2
* dce_rpc: Pass proper file id in file api from smb1
* decompress: Add support for streaming ZIPs
* detection: Use IP and port variables from the targeted policy
* doc: Remove http detained inspection from user manual
* doc: Update documentation for ips.states
* file_magic: Add pattern for pcapng
* flow: Add new flag to indicate elephant flow
* ftp_telnet: Implement init_partial_flush for ftp data
* ftp_telnet: Respect telnet_cmds config for raising 125:1
* host_attributes: Update api to reduce use of shared_pointer
* http2_inspect: Limit number of concurrent streams
* http2_inspect: Process rst_stream frame
* http_inspect: IPv6 authority in URI
* http_inspect: Javascript support cleanup
* http_inspect: Partial inspection for 0 length chunk
* http_inspect: Remove detained inspection
* http_inspect: Remove unused events
* http_inspect: Temporarily restore detained_inspection parameter
* iec104: Add documentation for iec104 service inspector
* iec104: Additional input sanitization, syntax, and style changes
* iec104: Integrate new iec104 protocol service inspector
* inspector_manager: Instantiate default binder as long as a wizard or stream are present
* ips_options: Update cursor position for relative pcre
* ipv4: Correct the calculation for illegal fragment offset checks
* log: Add printf format attribute to TextLog_Print() and clean up the fallout
* log: Base logging the Ethernet header on proto bits rather than DLT
* loggers: Fix excessive byte reordering when printing MPLS labels in CSV and JSON
* main: Fix accumulating and printing codec stats at run time
* managers: Enforce strict parsing for binder aliases
* managers: Pass the configuration to default module's end()
* managers: Perform sanity checks on set_alias() parameters
* memory: Free memory space while updating allocation
* module: Introduced new api to clear global active module counters
* module_manager: Enforce interest in global modules only in the default policy
* mpls: Add next layer autodetection and implement codec logging
* mpls: Refactor mpls.enable_mpls_overlapping_ip into packet.mpls_agnostic
* mpls: Remove enable_mpls_multicast option
* packet_capture: Add group filter for packet capture
* packet_tracer: Add daq buffer to hold daq logs
* perf_monitor: Fix finalizing JSON output files for trackers
* portscan: Fix decoy and distributed scan logic
* portscan: Fix delimiter for ports in config
* portscan: Fix IP scans not alerting
* protocols: Add initial support for multilayer compound codecs
* protocols: Add peg count for decodes that exceeded the max layers
* protocols: Consistently encapsulate exported protocol headers in the snort namespace
* reputation: Add peg count for total alerts
* reputation: Remove deprecated redundant terms
* rna: Discover NetBIOS name
* snort: Clear snort counter for modules, daq, file_id, appid
* snort: Update for DAQ_FlowStats_t structure and field name changes
* snort_config: Clean up and annotate command line config merge process
* snort_config: Remove unnecessary command line options
* stream: Always use latest splitter from tracker after paf_check
* stream: Do not update service from appid to host attributes if nothing is changed
* stream: Set block pending flag when a flow is dropped
* stream_tcp: Ensure flows aren't pruned while processing a PDU
* stream_tcp: Flush queued segments when FIN is received
* stream_tcp: Support data on SYN by default with or without Fast Open option
* trans_bridge: Lift the log() implementation from the root Ethernet codec
* wizard: Add support for sslv2 detection

2021-01-28: 3.1.1.0

* appid: Add support for snmpv3 report pdu
* appid: Always store container session api object in stash
* appid: Do not process sip event for an existing session after detector reload
* appid: Remove unused code; cleanup FIXIT comments related to reload
* appid: Send reload detectors and third-party messages to socket immediately if appid is not
  enabled
* codecs: Update tcp naptha check to make sure it is ipv4 traffic
* file_api: Remove file context after file name set if processing is complete
* file_api: Stop processing signature when type verdict is 'FILE_VERDICT_STOP'
* flow: Update direction and interface info in HA flow
* ftp: Use Stream packet holding to handle ftp-data EoF
* http_inspect: Add chunked processing to dev notes
* http_inspect: Provide file_id to set file name and read new return value
* http_inspect: Validate and normalize scheme
* http_inspect: Validate URI scheme length
* inspector: Add a global reference count for uses that are not thread specific
* lrucache: Changes for memcap for support constant cache objects with variable size
* managers: Clean all inactive inspectors warning about ones that are still referenced
* mime: Provide file_id to set file name and read new return value
* payload_injector: Inject settings frame
* rna: Minimize synchronization overhead

2021-01-13: 3.1.0.0

* appid: Store stats in map
* appid: Tear down third-party when appid gets disabled
* build: Add support for version sublevel and build via CMake
* dce_rpc: Handle Flow from File inspection
* host_cache: Add command to output host_cache usage, pegs, and memcap
* http2_inspect: Add total_bytes peg to track HTTP/2 data bytes inspected
* http_inspect: Abort on HTTP/2 connection preface
* http_inspect: Add total_bytes peg to track HTTP data bytes inspected
* http_inspect: Alert on truncated chunked and content-length message bodies
* http_inspect: Support stretch for Http2
* log: Reuse TextLog buffer for a large data;
  Thanks to Chris White for reporting the issue
* packet_io: IDS mode should not give blacklist verdict for Intrusion event
* rna: Fix version, vendor and user string comparison at maximum length
* rna: Perform appropriate filter check based on the event type
* rna: Revert rna performance optimizations
* rpc_decode: Implement adjust_to_fit for RPC splitter
* stream_tcp: Delete redundant calls to check if the tcp packet contains a data payload
* stream_tcp: Fix issues causing overrun of the pdu reassembly buffer, make splitters
  authoritative of size of the reassembled pdu
* stream_tcp: On midstream pickup, when first packet is a data segment, set flag on talker tracker
  to reinit seglist base seg on first received data packet
* stream_tcp: Remove obsolete flush_data_ready() function

2020-12-20: 3.0.3 build 6

* active: Fix falling back on using raw IP for active responses when no device is specified
* appid: Add support for apps, http host, url and tls host in HA
* appid: Allow checking appid availability for a given http/2 stream
* appid: Change terms used in code, logs and peg counts
* appid: Do not override http fields with empty values
* appid: Dump userappid configurations upon reloading third-party
* appid: For http2 flow, return service id as http2 when no streams are yet created
* appid: Mark reload third-party complete after unloading old library and creating new third-party
  context
* appid: Print more descriptive error message when lua detector registers invalid pattern
* binder: Pass service to get_bindings on flow service change
* binder: Specify service inspector type when getting a gadget instance
* build: Clean up various cppcheck warnings
* catch: Avoid using INTERNAL_CATCH_UNIQUE_NAME in our headers
* catch: Update to Catch v2.13.3
* dce_rpc: Fixed incorrect access of FileFlows while pruning the flow
* file_api: Fixed stats which weren't cleared when there were no stats for signature processing
* file_api: Handle resume block when multiple file rules are configured with store option enabled
* flow: Pause logging during timeout processing
* helpers: Handle SIGILL and SIGFPE with the oops handler
* high_availability: Add check for packet key equals HA key before consume
* host_attributes: Better error handling for reload to eliminate double free and memory leaks
* http2_inspect: Check for invalid flags
* http2_inspect: Fix bug with exceeding inspection depth
* http2_inspect: Fix empty queue access and some bookkeeping
* http2_inspect: Handle connection close during headers frames
* http2_inspect: Handle discard
* http2_inspect: HI error handling improvements
* http2_inspect: Improve error handling
* http2_inspect: Remove 0 length scan for most cases
* http_inspect: Explicit memory allocation for transactions and partial inspections
* http_inspect: Script detection for HTTP/2
* inspector_manager: Remove unused inspector_exists_in_any_policy() function
* inspector: Remove obsolete metapacket processing functionality
* main: Convert Request to shared_ptr to avoid memory problems
* main: Fix memory leak in reload_config() caused by incorrect code merge
* managers: Add inspector type in the help module output
* managers: Don't allow a referenced inspector to stall emptying the trash
* managers: Track removed inspectors during reload and call tear_down and tterm to release
  resources
* packet_io: Export forwarding_packet() function
* packet_tracer: Fix the debug session information for non-ip packets
* parser: Add escaping for double quotes and special chars in a rule body
* parser: Fix escape logic for --dump-rule-meta output
* reload: Reset default policies after failed reload
* request: Expose methods to be used in plugins
* rna: Do null check in the Inspector rather than the Module in the control commands
* rna: Generate new host event for CDP traffic
* rna: Make the mac cache persist over reload config
* rna: Reduce host cache lock usage to improve performance
* rna: Remove unused function
* rna: Replace some tabs with spaces as per style guidelines
* rna: Support data purge command
* rna: Support DHCP fingerprint matching and event generation
* rna: Use service ip and port provided by appid for DHCP discovery events
* shell: Change terms used in code, logs and peg counts
* shell: Support for loading configuration in lua sandbox
* snort: Add OopsHandlerSuspend for suspending Snort's crash handler
* stream: Fix stream clean up when going from enabled to disabled
* stream_ha: Only flush on HA deactivate if not in STANDBY, set HA state to STANDBY when new Flow
  is created
* stream_tcp: Initialize the alerts array to empty when a TcpReassembler instance is initialized
  or reset
* stream_tcp: Set interfaces in both directions

2020-11-16: 3.0.3 build 5

* appid: Add unit test to verify HA data for flow unmonitored by appid
* appid: Handle cppcheck warnings
* appid: Prefix http/2 decrypted urls with https://
* appid: Support client login failure event
* flow: Do not remove the flow during pruning/reload during IPS event with block action
* flow: Flesh out swap_roles() to swap more client/server fields
* flow: Set client initiated flag based on DAQ reverse flow flag, track on syn config, and syn-ack
  packet
* ftp: Handle FTP detection when ftp data segment size changes
* host_tracker: Ignore IP family when comparing SfIp keys in the host cache
* http2_inspect: Data frame redesign
* http2_inspect: Multi-segment reassemble discard bug fix
* http2_inspect: Perform hpack decoding on push_promise frames
* http2_inspect: Refactor data cutter
* http2_inspect: Refactor scan()
* http2_inspect: Remove const cast
* http2_inspect: Send push_promise frames through http_inspect
* ips_options: Don't move cursor in byte_math
* main: Set up logging flags globally to avoid dependencies on a particular SnortConfig object
* payload_injector: Refactoring
* payload_injector: Remove content length and connection for HTTP/2
* rna: Add command to delete MAC hosts and protos
* rna: Delete payloads when clients, services are deleted; add unit tests
* rna: Discover banner on service version or response events
* rna: Don't process packet in eval if eth bit not set
* rna: Log src mac from packet containing CDP message when host type change event is generated
* rna: Support banner discovery
* rna: Support change service event with null version and vendor
* rna: Support user login failure discovery
* smtp: Make sure the ssl search abandoned flag is preserved for reset
* stream_tcp: Remove redundant/unneeded asserts that check if tcp event is for a meta-ack
  psuedo-packet
* thread_config: Show thread ID when logging binding information
* trace: Add missing packet information to some of the messages

2020-10-27: 3.0.3 build 4

* actions: Add support to react for HTTP/2
* appid: Fix -Wunused-private-field Clang warning in service_state.h
* build: Various build fixes for OS X
* file_api: Remove deletion of file_mempool
* framework: Fix ConnectorConfig dtor to be virtual
* ips: Move IPS variables to sub-tables which designate type
* lua: Update default_variables with 'nets', 'paths', and 'ports' tables in snort_defaults.lua
* module: Fix modules that accept their configuration as a list
* payload_injector: Support pages > 16k
* rna: Add unit tests for TCP fingerprint methods
* snort: Remove support for -S option
* src: Clean up zero-initialization of arrays
* tools: Update snort2lua to convert custom variables into ips.variables.nets/.paths/.ports tables
* trace: Add timestamps in trace log messages for stdout logger

2020-10-22: 3.0.3 build 3

* actions: Update react documentation
* actions: Use payload_injector for react
* appid: Add service group and asid in AppIdServiceStateKey
* appid: Continue appid inspection after third-party identifies an application
* appid: Do not reset third-party session after third-party reload
* build: Updates for libdaq changes that introduce significant groups in flow stats
* codecs: Remove PIM and Mobility from bad protocol lists
* dce_rpc: Add ingress/egress group and asid in SmbFlowKey and Smb2SidHashKey
* doc: Tweak the template regex in get_differences.rb
* dump_config: Don't print names for list elements
* file_api: Add ingress/egress group and asid in FileHashKey
* file_magic: Update POSIX tar archive pattern
* flow: Add source/dest group id in flow key
* flow: Stale and deleted flows due to EOF should generate would have dropped event
* ftp_data: Add can_start_tls() support and generate ssl search abandoned event for unencrypted
  data channels
* host_cache: Add delete host, network protocol, transport protocol, client, service, tcp
  fingerprint and user agent fingerprint commands
* host_tracker: Implement client and server delete commands
* http2_inspect: Handle stream creation for push promise frames
* ips_options: Fix retry calculation in IPS content when handling "within" field
* lua: Use default IPS variables in the default config
* main: Add lua variables for snort version and build
* managers: Delete obsolete variable parsing code
* managers: Skip snort_set lua function for non-table top level keys in finalize.lua
* meta: Do not dump elided header fields or default message
* meta: Dump full rule field
* meta: Dump missing port field
* packet: Add two new apis to parse ingress/egress group from packet's daq pkt_hdr
* packet_tracer: Add groups in logging based on significant groups flag
* port_scan: Add group and asid in PS_HASH_KEY
* rna: Change ip to client instead of server for login events
* rna: Change logic for payload discovery, eventing
* rna: Conditionalize reload tuner registration on get_inspector()
* rna: Log user-agent device information
* rna: Move registration of reload tuner to configure()
* snort2lua: Update comments for deleted rule_state options
* ssh: Fix code indentation and CI breakage
* ssh: SSH splitter implementation
* stream: Initialize flow key's flags.ubits with 0
* stream_tcp: Don't attempt to drop 'meta_ack packets', there is no wire packet for these acks
* style: Clean up accumulated tabs and trailing whitespace
* trace: Refactor the test code
* trace: Skip trace reload if no initial config present
* utils: Add a generic function to get random seeds

2020-10-07: 3.0.3 build 2

* appid: Create events for client user name, id and login success
* appid: Inform third-party about snort's idle state during reload
* appid: Reload detector patterns on reload_config for the sake of hyperscan
* appid: Update appid to use instance based reload tuner
* binder: Allow binding based on address spaces
* binder: Allow directional binding based on interfaces
* binder: Enforce directionality, add intfs, rename groups, cleanup
* framework: Update packet constraints comparison to check only set fields
* host_tracker: Update host tracker to use instance based reload tuner
* http2_inspect: Fix frame padding handling
* http2_inspect: Free up HI flow data when we are finished with it
* http2_inspect: Stream state tracking
* http_inspect: Implement can_start_tls(), add support of ssl search abandoned event
* http_inspect: Support for custom xff type headers
* main: Change reload memcap framework to use object instances
* main: Remove deprecated rule_state module
* main: Update host attribute class to use instance based reload tuner
* normalizer: Move TTL configuration toggle to inspector configure()
* perf_monitor: Update perf monitor to use instance based reload tuner
* policy: Copy uuid, user_policy_id, and policy_mode when an inspection policy is cloned
* pop: Generate alert for unknown command if file policy is attached
* port_scan: Update port scan to use instance based reload tuner
* rna: Add event_time to rna logger events
* rna: Add payload discovery logic
* rna: Check user-agent processor early to skip some work
* rna: Port host type discovery logic
* rna: Set the thread local fingerprint processors during reload_config
* rna: Update rna to use instance based reload tuner
* rna: Update methods for user-agent processor
* rna: User discovery for successful login
* snort2lua: Convert rule_state into ips.states
* stream_tcp: Update trace messages to use trace framework
* stream: Update stream to use instance based reload tuner
* trace: Update parser unit tests
* wizard: Clean up parameter parsing and make it a bit stricter

2020-09-23: 3.0.3 build 1

* ac_bnfa: Disable broken fail state reduction
* appid: Check third party context version while deleting connections
* appid: Use third party payload if available for HTTP tunneled
* cmake: Support cmake build type configuration
* dce_rpc: Handle compound requests for upload
* dce_rpc: Modify logs to show if file context is found or not found
* dump_config: Sort config options before printing
* file_api: Update lookup and block timeout from config at file cache creation
* flowbits: Evaluate checkers after setters for fast pattern matches
* ftp: Add APPE to upload commands
* http2_inspect: Convert to new stream states
* http2_inspect: Fix how implement_reassemble uses frame_type
* http2_inspect: Refactor HI interactions out of frame constructors
* http_inspect: Extract filename from content-disposition header for HTTP uploads
* module_manager: Keep a list of modules supporting reload_module
* netflow: Cache support and more v5 decoding
* payload_injector: Don't inject if stream id is even
* profiler: Fix issue where flushed pattern matches caused rule_eval to be profiled under mpse
* reputation: Change terms used in code, logs, and peg counts
* rna: Add unit test to validate VLAN handling
* rna: Avoid conflicts with other fingerprint definitions
* rna: Service discovery with multiple vendor and version support
* rna: Support user agent fingerprints
* s7commplus: V3 header support
* search_engine: Fix peg type for max_queued
* stream_tcp: Add an assert to catch tcp state/event combination that should not occur
* stream_tcp: Add PegCount for tcp packets received with an invalid ack
* stream_tcp: Arrange TCP tracker member vars to optimize storage requirements, add helper
  functions to access private splitter functions
* stream_tcp: Delete redundant calls to flush data when FIN is received
* stream_tcp: Delete unused packet action flags, set action flags via its setter
* stream_tcp: Fix issues with stream_tcp handling of the TCP MSS option
* stream_tcp: Handle bad tcp packets consistently when normalizing in ips mode
* stream_tcp: Implement helper function to return true if the TCP packet is a data segment, false
  otherwise
* stream_tcp: Merge the setup methods of the TcpStreamSession and TcpSession classes into a single
  method in TcpSession
* stream_tcp: Refactor tcp handling of no flags to drop packet before any processing, don't
  generate event
* stream_tcp: Refactor tracker and reassembler classes to improve encapsulation and move member
  variables to appropriate class
* stream_tcp: Remove FIXIT-H because by definition an Ack Sent event in TcpStateNone means the
  SYN-ACK was not seen, so no way to do the check suggested
* stream_tcp: Remove FIXIT-H to add ack validation, the ack is already validated when processed on
  the listener side
* target_based: Support reload of host attribute table via signal as well as control channel
  command

2020-09-13: 3.0.2 build 6

* active: Remove per packet prevent trust action
* appid: Add check for nullptr before setting tls host
* appid: Clear services set in host attribute table upon detector reload
* appid: Detect SMTP after decryption
* appid: Dump user appid configuration on reload detectors
* appid: Generate events for service info changes
* appid: Pass snort protocol id instead of appid while creating future flow
* appid: Reorder third-party reload to keep only one handle open at a time
* appid: Send swap response for reload_odp and reload_third_party commands in control thread
* appid: Set payload to unknown for out-of-order flows
* appid: Skip detection for existing sessions after detector reload; rename reload_odp command to
  reload_detectors
* appid: Support json logging in appid_listener
* appid: Update appid stats for decrypted flows
* appid: Update appid warning messages to print module name in lowercase
* build: Fix minor cppcheck warnings
* build: Updates for libdaq changes to interface group field width and naming
* byte_jump: Fix jump relative to extracted length w/o relative offset
* cmake: Restore accidentally removed caching of static DAQ modules
* dce_rpc: Introduce smb2 logs
* doc: Update the config dump in JSON format (all policies)
* doc: Update the config dump in JSON format (main policy)
* doc: Update trace.txt with info about 'trace.modules.all' option
* dump_config: Add --dump-config="top" to dump the main policy config only
* dump_config: Dump config in JSON format to stdout
* file_api: Increase default max_files_per_flow limit to 128
* flow: Add a deferred trust class to allow plugins to defer trusting sessions
* flow: Disabled inspection for FlowState::RESET
* flow: Reset the flow before removing
* helpers: Add unit tests for special characters escaping
* helpers: Fix build on systems without sigaction
* helpers: Rework DiscoveryFilter to monitor IP lists based on interface rather than group
* helpers: Use sig_t instead of sighandler_t for better BSD compatibility
* host_tracker: Fix allocator unit test to work on 32-bit systems again
* http2_inspect: Convert circular_array to std:vector
* http2_inspect: Fix continuation frame check
* http2_inspect: Fix hpack dynamic table init
* http2_inspect: Prepare http2_inspect and http_inspect for HTTP/2 trailers
* http2_inspect: Refactor hpack decoding and send trailer to http_inspect for processing
* http_inspect: Declare get_type_expected const
* http_inspect: Don't use the URL to cache file verdicts for uploads
* http_inspect: Script detection
* http_inspect: Script detection and concurrency fixes
* http_inspect: Support hyperscan literal search for accelerated blocking
* http_method: Make available for fast pattern with first body section
* imap: Publish OPPORTUNISTIC_TLS_EVENT on successfull completion on START_TLS, add a new state to
  avoid publishing start_tls events multiple times
* ips_options: Ensure all options use base class hash and compare methods
* ips: Use the policies in the flow when creating pseudo packet
* main: Turn off signal handlers later to catch more during snort shutdown
* managers: Immediately stop executing inspectors when inspection is disabled
* mime: Fix off-by-1 error with filename and email id capture
* mime: Minor code cleanup
* netflow: Introduce netflow as a service inspector
* packet_io: Added reason for ActiveStatus WOULD
* packet_io: Do not allow trust unless the action is allow or trust
* payload_injector: Assume http1, if packet does not have a gadget
* payload_injector: Fix warning
* payload_injector: Support http2 injection
* payload_injector: Support translation of header field value with length > 127
* perf_monitor: Convert the perf_monitor inspector configure warnings to errors
* pop: Publish start_tls events, support for ssl search abandoned
* reputation: Change from group-based to interface-based IP lists
* rna: Add protocols on logging host trackers
* rna: Implement update_timeout for MAC hosts
* rna: Remove dependency on uuid library
* rna: Remove redefinition of USHRT_MAX
* rna: Removing unused command and exporting swapper
* rna: Support client discovery from appid event changes
* rna: Support service discovery from appid event changes
* rna: Tcp fingerprints configuration, storage, matching and event generation
* snort2lua: Remove obsolete and unused code
* snort2lua: Remove unused unit test files
* snort: Address fatal shutdown stability issues
* stream_ip: Fix zero fragment built-in rule triggering for some reassembly policies
* style: Replace some tabs that snuck in with proper spaces
* tests: Fix the majority of memory leaks in CppUTest unit tests
* trace: Add support for modules.all option
* trace: Update loggers to support extended output with n-tuple packet info
* utils: Add sys/time.h to util.h for struct timeval definition
* wizard: Fix the error message about invalid pattern

2020-08-12: 3.0.2 build 5

* cip: Fix the trailing parameter for the module
* dce_rpc: Set dce_rpc as a control channel inspector
* flow: Check expected flows in flow control and add direction swap flag to expected flows
* framework: Add an API to check if the module can be bound in the binder
* ftp: Add opportunistic TLS support
* ftp: Fix direction for active FTP data transfers
* helpers: Extend printed JSON syntax
* http2_inpsect: Fix for flush on data frame boundray w/o end of stream
* http_inspect: Do finish() after partial inspection
* lua: Add TCP port 80 binding to the connectivity and balanced tweaks
* main: Add printing modules help in JSON format
* managers: Print the instance type of the inspector module with --help-module
* rna: Add RNA MAC-based discovery logic
* rna: Discover network and transport protocols
* stream_tcp: Add check to prevent reentry to TCP session cleanup when flushing a PDU

2020-08-06: 3.0.2 build 4

* appid: Clear service appid entries in dynamic host cache on ODP reload
* appid: Generate event notification when dns host is set
* dce_rpc: Fix for smb crash while tcp session pruning
* dce_rpc: Fix for smb session cleanup issue
* dce_rpc: Use file name hash as file id
* doc: Add documentation for dumping consolidated config in text format
* flow: Fixing free_flow_data logic
* http_inspect: Code clean up
* http_inspect: Test tool enhancement
* main: Dump consolidated config in the text format
* rna: Fix redefined macro warnings in between unit-test tools
* rna: TCP fingerprint input and retrieval
* utils: Keep deprecated attribute table pegcounts

2020-07-28: 3.0.2 build 3

* active: Move Active enabled flag into SnortConfig
* appid: For http traffic, if payload cannot be detected, set it to unknown
* appid: Move appid data needed by external components to stash
* appid: Support ODP reload for multiple packet threads and new session
* dce_rpc: Improve PAF autodetection for heavily segmented TCP traffic
* doc: Split Snort manual into separate user, reference, and upgrade docs
* doc: Update default text manuals
* doc: Update extending.txt about TraceLogger plugin
* file_api: Log event generated when lookup timedout
* ftp_telnet: Remove global config variable shared between multiple threads to prevent data race
* http2_inpsect: Fix interaction with tool tcpclose
* http2_inspect: Fix stream_in_hi
* http2_inspect: General code cleanup
* http_inspect: Do partial inspections incrementally
* http_inspect: Reduce memory used by partial inspections
* main: Rename the config options to ignore flowbits and rules warnings
* parser: Add support for variables with each ips policy
* payload_injector: Add HTTP page translation
* payload_injector: Extend utility to support HTTP/2 (no injection)
* pub_sub: Added a method in HttpEvent to retrieve true client-ip address from HTTP header based
  on priority
* rna: Fingerprint reader class and lookup table for tcp fingerprints
* snort_defaults: Remove the NOTIFY, SUBSCRIBE, and UPDATE HTTP methods
* stream_tcp: Only perform paws validation on real packets, skip this on meta-ack packets
* stream_tcp: When clearing a session during meta-ack processing pass a nullptr as the Packet*
  parameter
* target_based: Add mutex lock to ensure host service accesses are thread safe
* target_based: Move host attribute peg counts from the process pegs to stats specific to host
  attribute operations
* target_based: Refactor host attribute to use the LruCacheShared data store class to support
  thread safe access
* target_based: Streamline host attribute table activate and swap logic on startup and reload
* trace: Add support for extending TraceLogger as a passive inspector plugin
* wizard: Abandon the wizard on UDP flows after the first packet
* wizard: Abort the splitter once we've hit the max PDU size
* wizard: Add peg counts for abandoned searches per protocol
* wizard: Improve wizard tracing to indicate direction and abandonment
* wizard: Properly terminate hex matching
* wizard: Report spell and hex configuration errors and warnings

2020-07-15: 3.0.2 build 2

* appid: Moving thread local ODP stuff to a new class
* binder: delete obsolete network_policy parsing code
* build: Fix static analyzer complaints about unused stored values
* daq: Fix calculation of outstanding packets stat to properly use the delta
* dce_rpc: adding support for multiple smbv2 sessions for same tcp connection
* dce_rpc: Invalid endpoint mapper message
* dce_rpc: SMB ID invalid memory access
* http_inspect: send MIME full message body for file processing
* main: add config options --ignore-warn-rules and --ignore-warn-flowbits to snort module
* mime: mime no longer overwrites file_data buffer for http packets
* smtp: generate SSL_SEARCH_ABANDONED event when no STARTTLS is detected
* smtp: support opportunistic SSL/TLS switch over
* stream_tcp: coding style improvements
* stream_tcp: eliminate direct references to the Packet* wherevever possible within the TCP state
  machine context
* stream_tcp: eliminate use of STREAM_INSERT_OK as return code, it conveyed no useful information
  and was ultimately unused
* stream_tcp: implement meta-ack pseudo packet as thread local that is reused on each meta-ack TSD
* stream_tcp: implement support for processing meta-ack information when present
* stream_tcp: meta-ack from daq is in network order not host, remove conversion from host to
  network
* stream_tcp: process meta-ack info in any flush policy mode
* trace: add support for DAQ trace filtering

2020-07-06: 3.0.2 build 1

* appid: Appid coverity issues
* appid: Create lua states and lua detectors in control thread
* appid: Delete stale third-party connections when reloading third-party on midstream
* appid: Fix the format of the IPv6 strings in the Service State unit tests
* appid: include appid session api in appid event
* appid: use configured search method for multi-pattern matching
* build: Eradicate u_int usage
* build: Fix unit tests to build and work properly on a 32-bit system
* build: Fix various cppcheck warnings about constness
* build: Increment version to 3.0.2
* build: Miscellaneous 32-bit build fixes
* build: Use sanity check results (HAVE_*) for optional packages in CMake
* cmake: Properly handle SIGNAL_SNORT_* options in configure_cmake.sh
* codecs: add tunnel bypass logic based on DAQ payload_offset
* dce_tcp: parse only endpoint mapper messages
* detection: remove checksum drop fixit
* detection: remove unused code
* framework: fix global data bus cloning during reload module and policy
* helpers: Add a signal-safe formatted printing utility class
* helpers: Add support for dumping a backtrace via libunwind on fatal signals
* helpers: Dump additional information to stderr when a fatal signal is received
* helpers: Revamp signal handler installation and removal
* http2_inspect: Make print_flow_issues() regtest-only
* inspectors: add a virtual disable method for controls
* ips: add http fast pattern buffers
* ips: add ips service vs buffer checks; add missing services
* ips: enable non-service rules when service is detected
* ips: minimize port group construction for any-any and bidirectional rules
* ips: refactor fast pattern selection
* ips: update detection trees for earliest header checks
* main: configure and set main thread affinity
* main: set thread type for main thread
* managers: format lua whitelist output and ignore internal whitelist keywords
* max_detect: detained inspection disabled pending further work
* mpse: remove unused pattern trimming support
* oops_handler: Operate on DAQ message instead of Snort Packets
* payload_injector: add payload injection utility
* regex: convert to same syntax as pcre plus fast_pattern option
* rna: Adding initial support for reload_fingerprint command
* rna: remove custom_fingerprint_dir from configuration
* snort_defaults.lua: remove unused AIM_SERVERS var
* snort: fix --dump-rule-meta with ips.states
* stream_ip: Avoid modifying the original fragmented packet during rebuild
* stream_ip: use lowercase fragmentation policy names for verbose output
* stream: lock xtradata stream_impl to avoid data race on logging
* trace: add thread type and thread instance id to each log message for stdout logger
* tweaks: enable file signature for sec and max until depth issue resolved
* tweaks: updates for efficacy and performance
* wizard: Add FTP pattern to recognize FileZilla FTP Server

2020-06-18: 3.0.1 build 5

* actions: on a reload_config() free the memory allocated for react page on previous configuration
  loading
* actions: refactor to store react page response in std::string
* active: add a facility to prevent a DAQ whitelist verdict
* appid: add api to check if appid needs inspection
* appid: add braces to fix static analysis complaint
* appid: add response message to reload_third_party
* appid: check fqn before registering rrt
* appid: for http2, if metadata doesn't give a match on payload, set payload id to unknown
* appid: free memory allocated when appid is configured initially and then not configured on a
  subsequent reload
* appid: lua APIs to get IP and port tunneled through a proxy
* appid: match http2 response to request
* appid: remove unnecessary stuff from appid apis
* appid: revert snort protocol id changes and fixed warnings
* appid: set appid_tlshost_bit when we set tls_cname
* appid: set snort protocol id on the flow and remove ssl squelch code
* appid: update cert viz API to handle subject alt name and SNI mismatch
* codecs: fix issues found by static analysis
* dce_rpc: suppport for DCE/RPC future session
* detection: do not apply global rule state to the empty policy
* doc: update user manual for trace feature
* file_api: making sure that file malware inspection is turned off and only file-type detection is
  enabled when file_id config is defined without any parameter
* flow: make client_initiated flag depend on the DAQ reverse flow flag
* hash: replace the cache entry if found
* host_cache: add new peg to module test
* host_cache: allowing module to accept 64 bit memcap value
* http2_inspect: fix hpack infractions
* http2_inspect: partial inspect with less than 8 bytes of frame header in the same packet
* http2_inspect: track memory usage for http_inspect flows in http2_inspect
* log: fix issues found by static analysis
* managers: add inspector execution and timing traces to InspectorManager
* packet: add client and server direction methods that use the client initiator flow flag
* parser: free memory allocated for RTN when SO rule load fails
* parser: print loaded and shared rules for each ips policy
* perf_monitor: fix count and interval during disable cli execution
* port_scan: cleanup port scan memory allocations in module tterm
* rpc_decode: remove unused config object
* search_engines: fix potential memory leaks and an error in a printed value
* service_inspectors: remove some redundant initializations and lookups, move some field
  initializations into the constructor
* shell: if initial load of snort configuration fails release memory allocated for modules and
  plugins
* snort2lua: deprecate react::msg option, display of rule message in react page not currently
  supported
* snort2lua: fix issues found by static analysis
* snort_config: only perform FatalError cleanup from main thread
* stream: add final check to free allocated memory when module tterm is called
* stream: fixed ip family in the flow->key during StreamHAClient::consume
* stream_tcp: fix issues for tcp simultaneous close
* stream_tcp: unconditionally release held packets that have timed out, regardless of flushing
* trace: add control channel command
* trace: add support for passing in the packet pointer to loggers
* trace: filter traces by packet constraints
* trace: fix for trace messages in the test-mode ('-T' option)
* trace: remove redundant include

2020-05-20: 3.0.1 build 4

* appid: Do not allocate DNS session for non-DNS flows and update memory tracker for HTTP sessions
* appid: Get inspector for the current snort config during reload
* binder: print configured bindings in show() method
* build: fix cppcheck warnings and typos
* coverity: fixed issues discovered by Coverity tool
* daq: Configure DAQ instances with total instances and instance IDs
* dce_rpc: code style cleanups
* dce_rpc: generate alert when dce splitter aborts due to invalid fragment length
* flow: If a retry packet does not belong to a flow, block it
* ftp_telnet: fix FTP race condition
* http2_inspect: change partial flush handling
* log: do not truncate config option names in ConfigLogger
* loggers: when logging alert only use inspector buffers and name when the inspector's paf
  splitter is assigned for the direction of the alert"
* main: Fixing some issues reported by Coverity
* managers: print alphabetically sorted verbose inspector config output within an inspection
  policy
* mpse: constify snort config args
* network_inspectors: Fixing a few minor issues reported by Coverity
* parser: print enabled rules for each ips policy
* search_tool: refactor initialization
* snort_config: constify Inspector::show and remove unnecessary logger args
* snort_config: make const for packet threads
* snort_config: minimize thread local access to snort_config
* snort_config: pseudo packet initialization
* snort_config: refactor access methods
* snort_config: use provided conf
* stream: add a configurable timeout for held packets
* stream: move held packet timeout to Stream and support changing it on reload
* stream_tcp: call splitter->finish() before reassemble() when flushing when PAF aborts due to gap
  in queued data
* stream_tcp: change the DAQ verdict from drop to blacklist for held packets that timed out
* stream_tcp: clear gadget from Flow object once fallback has happened in both directions
* stream_tcp: only clear gadget after both splitters have aborted
* stream_tcp: when paf aborts due to gap in data set splitter state to ABORT
* trace: move module trace configuration into the trace module

2020-05-06: 3.0.1 build 3

* appid: Do not process retry packets but continue processing future packets in AppId
* appid: Extract metadata for tunneled HTTP session
* appid: Make unit tests multithread safe
* appid: On API call store new values and publish an event for them immediately
* appid: remove old http2 support
* appid: store appids for http traffic in http session
* appid: support for multi-stream http2 session
* appid: Update miscellaneous appid on first decrypted packet
* build: add support for ccache
* file_api: fix file stats
* file_api: mark processing of file complete after type detection if signature not enabled
* http2_inspect: add peg count to track max concurrent http2 file transfers
* http2_inspect: fix handling leftover data with padding
* http2_inspect: protect against unexpected eval calls
* http2_inspect: support stream multiplexing
* http2_inspect: update padding check only for header and data frames
* http_inspect: add support for http2 file processing
* json: add stream formatter helper
* managers: sort the inspector list in inspection policy using the instance name
* memory: expose memory_cap.h to plugins
* parameter: reject reals assigned to ints
* rna: Update dev notes to describe usage
* snort: add classtype, priority, and references to --dump-rule-meta output
* snort: convert --dump-rule-{meta,state,deps} to json format
* so rules: allow #fragments in references in so rule stubs
* stream: Fix for stream pegs dumping zero values into perf_monitor_base.csv

2020-04-23: 3.0.1 build 2

* appid: Change sessionAPI to accomodate stream_index
* appid: detect payload for first http2 stream
* appid: Fix thread-safety issues in appid
* appid: mark third-party inspection as done for expected flows
* appid: Populate url for QUIC sessions by extracting QUIC SNI metadata from third-party
* appid: remove thirdparty processing for http2 traffic
* appid: remove unused code
* appid: remove unused config options and rename "debug" option
* appid: set up packet counters to make sure flows with one-way data don't pend forever
* appid: Support org unit in SSL lookup API and do not overwrite the API provided data
* codecs: Clean up CiscoMetaData implementation
* codecs: GRE checksum updated for injected and rewritten packets
* codecs: Update GRE flags and offset for injected packets
* control: Disable request unit-test in cmake if shell is disabled
* control: Fixing data races in request read and response
* file: apply cached verdict on already seen file
* file_magic: Update category for HWP and MSOLE2
* flowbits: eliminate extraneous FlowBitState
* flowbits: fix reload mapping
* flowbits: refactor implementation
* flowbits: relocate bitop.h to helpers
* flowbits: remove extraneous count
* flowbits: remove unused group support
* flow: track allocations for each flow, update cap_weights
* framework: Remove unused InspectorData template
* ftp_data: fix ids flushing at EOF
* ftp: whitelisting reason support
* host_tracker: Move all HostCacheAlloc template implementions to the header
* http2_inspect: discard split connection preface
* http2_inspect: flush pending data when a non-data frame is received
* http2_inspect: handle the case of leftover header only (no body)
* http2_inspect: support 0 length data frames
* http_inspect: add fragment to http_uri
* http_inspect: cut over to wizard on successful CONNECT response
* http_inspect: enhance processing of connect messages
* http_inspect: fix duplicated detained_inspection print in show()
* http_inspect: make script tag check case insensitive
* http_inspect: register extra-data callbacks in constructor
* hyperscan: simplify scratch memory initialization
* inspectors: designate service inspectors control channels for avc only
* inspectors: designate service inspectors for file carving
* inspectors: designate service inspectors for start tls
* inspectors: update verbose config output in show() method to a new format
* ips_context: add support to fallback to avc only
* ips: fix rule state mapping and policy lookup
* ips: remove plugins cruft from option tree node (rule body)
* latency: check if ip header is present before deferring it
* latency: use test_timeout config option to deterministically trigger latency events for ifdef
  REG_TEST
* loggers: Add SGT field to CSV and JSON loggers
* main: Make test_log() static in snort_debug.cc
* managers: print inspectors' config output for every inspection policy configured
* metadata-filter: apply to so rule stubs
* output: allow error messages in quiet mode
* packet_io: log daq batch size
* packet_io: log daq pool size
* perf_monitor: Enable or disable flow-ip-profiling using shell commands
* plugin_manager: make erase from plug_map safer
* plugin_manager: make sure --show-plugins option picks up SO plugins
* reload: update ReloadError response messages to use consistent wording across all messages
* session: remove unused IPS option
* sip: Support pinhole for sip early media
* snort2lua: make qos configuration values deleted from firewall
* snort: add --dump-rule-deps
* snort: add --dump-rule-state
* snort: add flowbits set and checked to --dump-rule-meta
* snort: add rule text to --dump-rule-meta
* snort: enable --dump-rule-meta to work without a conf
* snort: initial implementation of --dump-rule-meta
* snort: remove inappropriate fatal errors
* snort: remove unused --pcap-reload option
* so rules: allow stub gid:sid:rev to override so
* so rules: allow stub header to override so header
* stream_tcp: remove unused session printing cruft
* target_based: refactor host attribute table logic into a c++ class, eliminate dead code
* target_based: refactor to improve design of the host attribute classes
* target_based: refactor to load host attribute table from file
* time: make packet_gettimeofday public
* trace: refactor stdout/syslog logging of trace into logger framework

2020-03-31: 3.0.1 build 1

* analyzer: Send detained packet event when a packet is held
* appid: use http2 inspector for detection even if third-party module is present
* build: Increment version to 3.0.1
* dce_rpc: Fixed missing space in string
* doc: add FIXIT-E description
* http2_inspect: handle Cl and TE headers, and end_stream flags set on headers frames
* http2_inspect: multiple data frames support
* http_inspect: added FIXIT for thread safety
* http_inspect: eliminate empty body sections for missing message bodies
* latency: remove action config option and convert the log handler to trace_log message
* mime: fix data race in mime config
* modules: Support verbosity level for module trace options, modify trace logging macros
* service_inspectors: standardize verbose config startup output for SMTP, POP and IMAP inspectors
* snort2lua: remove conversion of deprecated options pkt-log and rule-log
* so_rule: fix reload of shared object rules that use flow data
* src: update high priority "to be fixed" comments (FIXIT-H)
* stream_tcp: Out-of-order ACK processing fix

2020-03-25: build 270

* active: Base hold_packet() decision on DAQ message pool usage
* active: Fix direction of RST packet being sent to server
* active: Move packet hold realization for Stream detainment to verdict handling
* active: Send entire buffer at once when send_data uses ioctl
* appid: Adding UT for client_app_aim_test
* appid: Fix SMB session data memory leak
* appid: Include DNS over TLS port for classification
* appid: Restart service detection on start of decryption
* appid: Support appid detection for outer protocol service
* appid: Support detection for first stream in http/2 session
* binder: Ignore the network_policy binding
* build: Bump the C++ compiler supported feature set requirement to C++14
* build: Don't try to use libuuid headers/libraries when not found;
  Thanks to James Lay <jlay@slave-tothe-box.net> for reporting the issue
* build: Refactor included headers
* codecs: Add new proto bit for udp tunneled traffic
* codecs: Add vxlan codec
* dce_rpc: Inspect midstream sessions for file inspection
* file_api: Reading the new data for the overlapped file_data
* filters: Update threshold tracking functions
* flow: Allow the ExpectCache to force prune, so that we can always make room when the cache is
  full
* flow: Change the ExpectCache prune logic to only remove a specified number of oldest entries,
  regardless of node expiration time
* flow: Do away altogether with the loop in ExpectCache::prune, just remove one, only when the
  cache is full
* http2_inspect: Refactor data cutter - preparation for multi packet processing
* http2_inspect: Support single data frame sent to http, multiple flushes
* http2_inspect: Update dev notes with memory calculations
* http_inspect: Create http2 message body type
* http_inspect: Gzip detained inspection
* http_inspect: Refactor print_section for message bodies
* loggers: Update usage to GLOBAL for all loggers
* lua: Enable a rewrite plugin in a default config
* main: Check if flow state is blocked while applying verdicts
* main: Setting higher maximum pruning when idle
* snort2lua: Convert a replace option to a rewrite plugin/action
* snort2lua: Don't print out network_policy binding
* stream: Short-circuit stream when handling retry packets in no-ack mode
* stream_tcp: Cancel hold requests on the current packet when flushing
* stream_tcp: Finalize held packets in TcpSession::clear_session()
* stream_tcp: Moved retry check to TcpSession::process

2020-03-12: build 269

* active: Add ability to inject resets and payload via IOCTLs
* appid: Add support for third-party reload on midstream session
* appid: detect apps using x-working-with http field in response header
* appid: Enhance ssl appid lookup api to store SNI and CN provided by SSL for app detection
* appid: fix thread-safety issues in mdns detector
* appid: handle CERTIFICATE STATUS handshake type in SSL detector
* appid: move client/service pattern detectors and service discovery manager to odp context
* appid: Support third-party reload when snort is running with multiple packet threads
* base64_decode: use standard detection context data buffer
* build: fix build on big-endian systems
* build: Fix LibUUID detection on OS X
* build: Fix various build issues on FreeBSD and OS X
* build: refactor trace logs
* build: tweak includes
* build: use const and auto references where possible
* byte_math: Snort2 bug fix port of integer over and under flow detection
* classifications: update implementation with unordered map
* classifications: use consistent variable names
* cmake: Fix building without lzma library
* detection: added support for trace config option to take a list of strings with verbosity level
  instead of bitmask
* detection: refactoring updates to detection, moved DetectionModule into a separate file
* flow: added initiator bytes/packets onto flow
* flow: Add missing time.h include for struct timeval
* flow: free the flow data before deleting the actual flow
* flow: turn off deferred whitelist on DONE if no whitelist was seen
* flow_cache: fix memory deallocation bug due to inverted return value from hash release node
* framework: add generic conversion of trace strings to bitmaks
* ftp: Whitelist ftp session after max sig depth reached
* ghash: fix thread race condition with GHash member variables when a GHash instance is global
* hash: add unit tests for new HashLruCache class
* hash: delete unused sfmemcap.[h|cc] and remove unnecessary includes
* http2_inspect: abort for nhi errors
* http2_inspect: send data frames to http - full frames only in a single flush
* http_inspect: change http_uri to only include path and query for absolute and absolute path uris
* http_inspect: improve precautions for stream interactions
* http_inspect: Properly mock HttpModule::peg_counts in http_transaction_test
* main: do FileService::post_init after inspectors are configured
* parser: remove legacy parsing code
* plugin_manager: add support for reload so_rule plugins
* pub_sub: add http2 info to http pub messages
* reference: update implementation with unordered map
* reload: add description of reload error to the response message of the reload_config command
* reputation: remove reputation monitor flag from packet, track verdict on flow
* rules: add constructors for references and classifications
* rules: fix warnings and startup counts for duplicates
* rules: remove cruft
* rules: simplify implementation of services, classifications, and references by using std::string
* rules: update --gen-msg-map to include all configured rules with references
* service_inspectors: added counters to track total number of data bytes processed in SMTP, POP,
  SSH and FTP
* service: update implementation to vector
* sfdaq: convert parsing related error messages in DAQ init to ParseErrors
* sfdaq: Made get_stats public for plugins
* smb: Fix malware over size 131kb not being detected in SMBv2/SMBv3
* snort_config: footprint REG_TEST, no check for stream inspector add/rm, etc
* stats: update shutdown timing stats
* stream: Addressing inconsistent stream stats and some data races
* stream_ip: added counters to track total number of data bytes processed
* stream_tcp: no_ack applies only to ips mode
* stream_udp: added counters to track total number of data bytes processed
* style: remove tabs and too long lines
* utils: add unit tests for MemCapAllocator class
* utils: create memory allocation class based on sfmemcap functionality
* utils: handle out-of-range time
* xhash: refactor XHash and HashFnc to eliminate c-style callbacks and simplify ctor options
* xhash: rename hashfcn.[cc|h] to hash_keys.[cc|h]
* xhash/zhash: refactor duplicated code into a common base class, xhash/zhash will subclass this
  new base class
* zhash: make zhash a subclass of xhash, eliminate duplicate code
* zhash: refactor to use hash_lru_cache and hash_key_operations classes

2020-02-21: build 268

* appid: Adding support for appid detection on decrypted SSL sessions
* appid: Adding support for wildcard ports in static host port cache
* appid: clean up ENABLE_APPID_THIRD_PARTY from configure_cmake
* appid: cleanup terminology
* appid: delete odp context on exit
* appid: detect payload for http tunnel traffic
* appid: do not reload third party on reload_config
* appid: Don't mark HTTP session done if the ssl detector is still in progress
* appid: Fix array initialization on Appid
* appid: get rid of ENABLE_APPID_THIRD_PARTY flag
* appid: handle invalid uri in http tunnel traffic
* appid: load app mapping data to odp context
* appid: move dns, sip, ssl and http pattern matchers to odp context; move client discovery
  manager to odp context
* appid: move odp config, host-port cache and length cache to a separate class OdpContext; remove
  obsolete port detector code
* appid: reset tp packet counters each time we do reinspect
* appid: support third party reload when snort is running with single packet thread
* bufferlen: match on total length unless remaining is specified
* build: Clean up accumulated tabs and trailing whitespace in the code
* build: clean up non-hyperscan builds
* build: Fix more Clang 9 compiler warnings
* build: Remove some extraneous semicolons (compiler warnings)
* build: Rename parameters that shadow class members (compiler warnings)
* build: Updates across the board for stricter Clang const-casting warnings
* catch: Update to Catch v2.11.1
* cip: explicitly include sys/time.h header
* codecs: Use unions for checksum pseudoheaders
* content: add hyperscan content literal matching alternative to boyer-moore
* content: delete flawed hyper search test
* content: use hs_compile if hs_compile_lit is not available
* copyright: update year to 2020
* dce_tcp: fixup flow data handling
* detection: add config option to enable conversion of pcre expressions to use the regex engine
* detection: add hyperscan_literals option
* detection: add pcre_override to enable/disable pcre/O
* detection: signature evaluation looping based on literal contents only (exclude regex)
* doc: manual updates for HTTP/2
* doc: update documentation for lua whitelist
* doc: update reload_limitations.txt
* file_api: enable Active when there are reset rules in the file policy
* framework: introduce ScratchAllocator class to help with scratch memory management
* gtp_inspect: fix default port binding
* hash: refactor ghash implementation to convert it to an actual C++ class
* hash: refactor key compare function prototype and functions to return boolean
* hash: refactor to move common definitions into hash_defs.h
* hash: refactor xhash to be a real C++ class
* host_tracker: Check lock in a separate thread in unit-test
* host_tracker: make current_size atomic to save some locks
* host_tracker: Support host_cache reload with RRT when memcap changes
* http2_inspect: add transfer encoding chunked at end of decoded http1 header block
* http2_inspect: data frame http inspection walking skeleton first phase
* http2_inspect: fast pattern support
* http2_inspect: fix string decode error
* http2_inspect: frame data no longer in file_data
* http2_inspect: integration with NHI
* http2_inspect: support disabling detection for uninteresting HTTP/2 frames
* http2_inspect: support HPACK dynamic table size updates
* http_inspect: add http_param rule option
* http_inspect: gzip splitting beyond request_depth should use correct target size
* http_inspect: no duplicate built-in events for a flow
* http_inspect: patch H2I-related xtra data crash
* http_inspect: process multiple files simultaneously over HTTP/1.1
* http_inspect: refactoring
* http_inspect: update test tool to support the HTTP/2 macros and new insert command
* http_inspect: when detection is disabled, disable all rules not just content rules
* http_inspect/http2_inspect: H2I unified2 extra data logging
* hyperscan: convert thread locals to scan context
* inspectors: ensure correct lookup by type, name, or service
* inspectors: print label for type and alias in inspector manager. Remove printing module name in
  inspectors ::show() method
* ips: alert service rules check ports
* ips_pcre: compile/evaluate pcre rule option regular expressions with the hyperscan regex engine
  when possible
* ips_pcre: support the O & R modifiers when converting pcre to regex
* ips: refactor rule parsing
* ips: remove dead code from rule parser
* ips: use service "file" instead of "user"
* loggers: update vlan logging in csv and json loggers
* lua: Added missing file magic pattern for FLIC
* lua: Added missing file magic pattern for IntelHEX
* lua: fix typo in default smtp's alt_max_command_line_len
* lua: update default lua files to whitelist the defined tables
* main: add verbose inspector output during reload
* main: make IPS actions (reject, react, replace) configurable per-IPS policy
* main: move config_lua to Shell::configure
* memory: Treating config value memory.cap as per thread instead of global
* metadata: add --metadata-filter to load matching rules only
* mime: support simultaneous file processing of MIME-encoded files over HTTP/1.1
* module_manager: add snort_whitelist_append and snort_whitelist_add_prefix FFIs
* normalizer: disable all normalizations by default except for tcp.ips
* packet_io: provide default reset action (bidirectional reset for TCP, ICMP unreachable for the
  rest)
* packet_io: refactor Active and IPS Actions to start disentangling them
* parser: add service http2 to http rules
* parser: store local copy of service name
* pcre: ensure use of maximal ovector size and simplify logic
* port_scan: Supporting reload config when memcap changes
* protocols: provide direct access to the CiscoMetaData layer
* regex: convert thread locals to scan context
* reload: eliminate FatalError calls that can't happen because snort_calloc always returns valid
  memory
* rna: use standard uint8_t type instead of u_int8_t
* search_engine: trivial reformatting
* smtp: update defaults to better align with Snort 2
* snort2lua: conversion of path containing variables
* snort: add new warn flag warn-conf-strict that will throw out warning when table is not found
* snort: Adding some verbose logs for appid, file_id, and reputation inspectors
* stream_tcp: ensure that flows with mss and timestamps are picked up on syn
* tweaks: set reasonable stream_ip.min_fragment_length values
* tweaks: update per new normalizer defaults
* tweaks: update policy configs to better align with Snort 2

2019-12-20: build 267

* appid: Adding command for third-party reload
* appid: cleanup unused code
* binder: assitant gadget support
* build: Const-ify reference arguments as suggested by cppcheck
* catch: Add infrastructure for standalone Catch unit tests
* catch: Update to Catch v2.11.0
* codec: Added GRE::encode method
* control: Convert IdleProcessing unit tests to standalone Catch
* dce_rpc: Convert HTTP proxy and server splitter unit tests to standalone Catch
* file_api: When multiple files are processed simultaneously per flow, store the files on the
  flow, not in the cache. Don't cache files until the signature has been computed
* file_magic: add file magic for .jar, .rar, .alz, .egg, .hwp and .swf files
* framework: Convert parameter and range unit tests to standalone Catch
* gtp: alerts should be raised for missing TEID in gtp msg
* helpers: Convert Base64Encoder unit tests to standalone Catch
* http2_inspect: add Stream class
* http2_inspect: parse settings frames
* http_inspect: support limited response depth
* ips: do not use includer for any rules file includes
* ips: fix --show-file-codes for inclusion from -c file
* lru_cache_shared: added find_else_insert to add user managed objects to the cache
* lua: Convert LuaStack unit tests to standalone Catch
* lua: Link lua_stack_test against libdl to handle the static luajit case
* packet_capture: ignore PDUs and defragged packets, include non-IP packets
* perf_monitor: Convert CSV, FBS, and JSON formatter unit tests to standalone Catch
* perf_monitor: tuning for flow_ip_memcap on reload
* profiler: Convert MemoryContext and ProfilerStatsTable unit tests to standalone Catch
* reload: fix issue where resource tuning was not being called when in idle context
* rule_state: allow empty tables
* search_engine: fix expected count of MPSEs when offloading
* sfip: Convert SfIp unit tests to standalone Catch
* sfip: Use REG_TEST-style IP stringification for standalone Catch tests
* stream_tcp: fix TcpState post increment operator to stop increment at max value (and use
  correct max value)
* stream_tcp: refactor stream_tcp initialization to create reassemblers during plugin init
* stream_tcp: refactor to initialize tcp normalizers during plugin init
* stream/tcp: Remove some unused Catch includes
* time: Convert periodic and stopwatch unit tests to standalone Catch
* utils: Convert bitop unit tests to standalone Catch

2019-12-04: build 266

* appid: Add new pattern to pop3, don't concatenate ssl certs, use openssl-1.1 compliant APIs
* appid: Enabling host cache for unknown SSL flows
* appid: Fix for better classification on pinholed data session and control session for
  rshell/rexec
* appid: Format detected apps stats in columns akin to file stats
* appid: Handle memcap during reload_config using RRT
* appid: Minor cleanup
* cmake: Cache static DAQ module info in FindDAQ
* file_api: Fixed eventing when FILE_SIG_DEPTH failed when store files enabled
* flow: Add ability to defer whitelist verdict
* flow: Clean up unit test compiler warnings
* flow: Disabling the inspection if the Flow state is BLOCK
* http2_inspect: Generate status lines for responses and be more lenient on RFC violations
* http2_inspect: Implement hpack dynamic index lookups
* http_inspect: Implement show method for verbose config output
* http_inspect: Update user manual for detained inspection
* hyperscan: Select max scratch from among all compiler threads
* ips: Add support for parallel fast-pattern MPSE FSM compilation
* ips: Only use multiple threads for rule group compilation at startup
* ips: Support 2 rule vars same as Snort 2
* mpse: Only hyperscan currently supports parallel compilation
* port_scan: Only update scanner for ICMP if we have one
* profiler: Fix module profile for multithreaded runs
* search_engine: Ensure configured search_method is applied to search tools
* search_engine: Process intermediate fast-pattern matches in batches of 32 same as Snort 2
* search_engine: Raise an error if any MPSE compilation fails
* sfip: Replace copy setter with implicit copy constructor
* stats: Removal of mallinfo as it only support 32bit
* stream_tcp: Move and update the libtcp source files to the tcp source directory to consolidate
  the stream tcp code into one component (libtcp goes away)
* stream_tcp: Updates from PR review comments

2019-11-22: build 265

* analyzer_command: support resource tuning on reload
* appid: Adding Lua-C API to handle midstream traffic
* cip: ips rule support for Common Industrial Protocol (CIP)
* ftp: handling multiple ftp server config validation
* detection: disable rule evaluation when detection is disabled for offload packets
* detection: fix post-inspection state clearing issue
* flow: check if there are offloaded packets in the flow before clearing out the alert count
* http2_inspect: add frame class and refactor stream splitter
* http2_inspect: fix unit tests to build without REGTEST defined
* main: Improve performance of control connection polling
* plugin_manager: allow loading individual plugin files in plugin-path
* reject: Setting defaults for reset and control options
* snort: update reload resource tuner to return status indicating if there is work to be done in
  the packet thread
* stream: register reload resource tuner unconditionally. move checks for config changes to the
  tuner tinit method
* stream_tcp: fix state machine instantiation
* wizard: handle NBSS startup in dce_smb_curse

2019-11-06: build 264

* appid: Handle DNS responses with compression pointers at last record
* dce_smb: deprecate config for smb_file_inspection, use smb_file_depth only
* detection: negated fast patterns are last choice
* http2_inspect: fix bugs in splitting long data frames and padding
* http_inspect: change accelerated_blocking to detained_inspection
* http_inspect: remove deprecated @fileclose command from test tool
* imap, pop, smtp: changed default decode depths to unlimited
* ips: define a builtin GID range to prevent unloaded SIDs from firing on all packets
* ips_option::enable: fix dynamic plugin build
* lua: tweak default conf and add tweaks for various scenarios
* normalizer: make tcp.ips defaults to true
* port_scan: increase default memcap to a more reasonable 10M
* s7commplus: Initial working version of s7commplus service inspector
* search_engine: stop searching if queue limit is reached
* stream: implement reload resource tuner for stream to adjust the number of flow objects as
  needed when the stream 'max_flows' configuration option changes
* telnet: fix check_encrypted help string

2019-10-31: build 263

* appid: for ssl sessions, set payload id to unknown after ssl handshake is done if the payload id
  was not not found
* appid: check inferred services in host cache only if there were updates
* appid: Updating the path to userappid.conf
* build: Clean up snort namespace usage
* build: generate and tag build 263
* binder: Use reloaded snort config when getting inspector
* codecs: Relax requirement for DAQ packet decode data offsets when bypassing checksums
* content: rewrite boyer_moore for performance
* data_bus: add unit test cases
* detection: enhance fast pattern match queuing
* dns: made changes to make sure DNS parsing is thread safe
* doc: update default manuals
* file_api: Put FileCapture in the snort namespace
* ftp: fix for missing prototype warning
* ftp: catch invalid server command format
* http_inspect: test tool single-direction abort fix
* http_inspect: add more config initializers
* http2_inspect: generate request start line from pseudo-headers
* http2_inspect: abort on header decode error
* http2_inspect: stop sharing a variable between scan and reassemble
* http2_inspect: decode indexed header fields in the HPACK static table
* http2_inspect: Move HPACK decompression out of stream splitter into a separate class
* http2_inspect: Abort on bad connection preface
* http2_inspect: cleanup
* http2_inspect: discard connection preface
* ips: add states member, similar to rules, by convention use for rule state stubs with enable
* mime: Put MailLogConfig in the snort namespace
* packet: fix reset issues
* packet_io: do not retry packets that do not have a daq instance
* policy: Avoid unintended insertion of policy into map if it does not exist
* pub_subs: made default pub_subs policy-independent
* rule_state: deprecat, replace with ips option enable to avoid LuaJIT limitations
* stream_tcp: fix stability issues
* stream_tcp: If no-ack is on, rewrite ACK value to be the expected ACK

2019-10-09: build 262

* analyzer: move setting pkth to nullptr to after publishing finalize event
* analyzer: publish other message event for unknown DAQ messages
* appid: add support for bittorrent detection over standard ports
* appid: add support for Lua detector callback mechanism
* appid: add support for wildcard ports in host tracker
* appid: extract forward ip from http tunneled traffic and use it for dynamic host cache lookup
* appid: fix populating dns_query for DNS traffic
* binder: allow binder to support global level service inspectors
* binder: remove global check for stream inspectors and revert module_map changes
* codecs: fix checksumming a single byte of unaligned data
* codecs: use checksum validation from DAQ packet decode data when available
* detection: consistently prefer service rules over port rules
* detection: do not split service groups by ip proto to avoid extra searches
* detection: map file rules to services
* detection: non-service rules must match on rule header proto
* detection: remove cruft from match accumulator
* detection: remove more cruft from match tracker
* detection: remove the inappropriate match tracker from mpse batch setup
* detection: remove unnecessary match data from eval context
* detection: support alert file rules w/o optional services
* detection: update trace to indicate eval task
* detection: use reference for signature eval data
* doc: add Snort2Lua note on ips rule action rewrite
* flow: check if control packet has a valid daq instance before setting up daq expected flow and
  add pegcounts for expected flows
* flow: patch to allocate Flow objects individually on demand. Once allocated the Flow objects are
  reused until snort exits or reload changes the max_flows setting
* flow: when walking uni_list stop before reaching head
* helpers: discovery filter support for zone matching
* helpers: implement port exclusion in discovery filter
* http2_inspect: cut headers from frame_data buffer
* http2_inspect: parse hpack header representations and decode string literals
* http2_inspect: validate connection preface
* ips_options: minor code style changes
* libtcp: turn off no-ack mode if packet is out of order
* lua: added move constructor and move assignment operator to Lua::State to fix segv
* lua: fixed whitespace to match style guidelines
* managers: add null check in reload_module to prevent crash when trying to reload module that has
  not been configured
* profiler: increase width of checks and alloc fields so values don't run together
* protocols: remove reference to obsolete DAQ_PKT_FLAG_HW_TCP_CS_GOOD flag
* pub_sub: replace DaqMetaEvent and OtherMessageEvent with DaqMessageEvent
* reputation: prevent reload module crash when reputation is not configured in lua at startup
* reputation: SIDs for source and destination-triggered events added
* snort2lua: convert snort2 port bindings into snort3 service bindings for inspectors configured
  in wizard and add --bind-port option to enable port bindings conversion
* snort2lua: remove identity related options from firewall
* snort2lua: reset the sticky buffer name while converting unchanged sticky rule options and
  file_data
* stream: clean up cppcheck warnings
* stream: clean up update_direction
* stream: code cleanup and dead-code removal
* unit-tests: fix compiler warnings that snuck into CppUTest unit tests
* utils: prevent integer overflow/underflow when reading BER elements

2019-09-12: build 261

* analyzer: Process retry queue and onloads when no DAQ messages are received
* appid: Enabled API for SSL to lookup appid
* appid: Support FTP banners on multiple packets with split response code
* build: Address miscellaneous cppcheck warnings
* build: Const-ify reference arguments as suggested by cppcheck
* build: Update CMake logic for unversioned LibSafeC pkg-config name
* doc: add bullets for $var parameter names and maxXX limits
* http_inspect: accelerated blocking for chunked message bodies
* http2_inspect: send raw encoded headers to detection
* managers: Make InspectorManager::thread_stop() a no-op if thread_init() was never called
* rna: generate an RNA_EVENT_CHANGE when a host is seen after the last log event and the current
  time is past the update timeout
* rna: support for bidirectional flow with UDP, IP, and ICMP traffic
* rna: Support for filtering rna events by host ip
* rule_state: switch from regex parameter names to simpler parsing
* snort2lua: only emit max_flows and pruning_timeout options in converted lua file if the option
  is used in the snort2 conf file
* stream: fix problem with accelerated blocking partial inspection
* style: update link for google c++ style guide

2019-08-28: build 260

* appid: handle 'change cipher spec' in 'server hello' to allow some app detection for tls 1.3
  traffic
* binder: updated change_service event to support service reset via wizard
* host_tracker: derive LruCacheSharedMemcap from the general LruCacheShared that tracks size in
  bytes, rather than number of items and instantiate host_cache from LruCacheSharedMemcap
* http2_inspect: Remove pkt_data buffer option
* reload: fix coding style issues, support multiple in progress analyzer commands, support
  associated AC state for execute method, move reload tune logic for ACSwap to the execute command
* rna: Support for rna unified2 logging
* stream_tcp: clear consecutive small segs count upon non-small segs only

2019-08-21: build 259

* analyzer_command: Import into snort namespace and add the ability to retrieve the DAQ instance
  from an Analyzer
* appid: delay port-based detection until a non-zero payload packet is seen for the session
* appid: fix discovery unit test that was failing intermittently
* appid: Fix for app name not getting evaluated for port/protocol based detectors
* appid: support for bittorrent detection when UDP tracker packet arrives after the TCP resumed
  session has already started
* build: Fix miscellaneous cppcheck warnings
* codec: Adapt to new DAQ message metadata source for Real IP/port info
* file_api: generate events each time file is seen, not just first time
* finalize_packet: pass verdict by reference in inspector event
* flow: add virtual destructor to stash generic object
* flow: Bypass HA write for unsupported Tunnel flows
* flow: delete stale flow on receiving NEW_FLOW flag
* flow: if no 'get_ssn' handler configured then skip processing of the flow
* flow: introduced variable for handling idle session timeouts and flag for actively pruning flows
  based on the expire_time
* flow: make a single flow cache for all the protocols
* flow: refactor flow config object to work with single flow cache concept
* flow: refactor uni list managment into a separate class and instantiate an instance for ip flows
  and another for all non-ip flows
* flow: release session object allocated for a flow when the Flow object is reused and the PktType
  of the new flow is different from the previous use
* flow: Add packet tracer message when a new session is started
* ftp_telnet: add support for ftp file resume block by calculating path hash used as file id
* hash: add back size(), get_max_size() and remove() functions to lru_cache_shared
* hash: add unit test for explicitly testing get / set max size
* host_cache: Refactoring code to fix multithreading issues and to remove redundancy
* http2: huffman string decode
* http2_inspect: add HI test tool
* http_inspect: remove 0-byte workaround
* ips_options: add ber_data and ber_skip
* main: Implement reload memcap framework
* pcre: add peg counts for PCRE_ERROR_MATCHLIMIT and PCRE_ERROR_RECURSIONLIMIT return status from
  pcre_exec()
* reputation: Fixed issues with reputation monitor
* rna: Add new hosts with IP-address into host cache
* snort2lua: Combine proto specific cache options for max_session in one max_flows option
* stream_tcp: add API for switching to no_ack mode
* stream_tcp: fix 3-1-2 ordering markup
* stream: update checks for modified stream config to work with updates to stream config options
* stream: updated the protocol setup and process logic of TCP,UDP,IP,ICMP and USER sessions for
  setting and updating idle session timeouts
* time: Make TscClock fail to compile on non-x86/AArch64 systems
* wizard: Avoid host cache service insertion since we are using flow service
* xhash: Ported sfxhash_change_memcap() from snort2 to snort3

2019-07-17: build 258

* analyzer: 1024 contexts max is a better default until configurable
* appid: fix header order in appid_session
* codec: add support of ignore_vlan flag from daq header
* detection: allocate scratch after configuration
* detection: immediately onload after offloading when running regression tests
* detection: on PDUs change search order to set check_ports correctly
* detection: reduce hard number of contexts to work with pcap default
* detection: start offload threads before packet threads are pinned
* detection: use offload_threads = N with -z = 1
* flow: Extend stash to support uint32_t and make it SO_PUBLIC
* flow: Fixes for DAQ-backed HA implementation
* flow: remove config.h from flow_stash_keys
* high_availability: high availability support in Snort2Lua
* host_cache: Adding command and config option to dump hosts
* host_cache: Closing va_list after usage using va_end
* http2: decode HPACK uint
* http2: hpack string decode
* http_inspect: perf improvements
* http_inspect: send headers to detection separately
* ips: add missing non-fast-pattern warning
* ips: refactor fast pattern searching
* mpse: api init and print methods are optional
* no_ack: Purge segment list withouth waiting for ack when using no_ack feature
* pcre: cap the pcre_match_limit_recursion based on the stack size available
* profiler: convert ips options to use optional profiles
* profiler: eliminate deep profiling
* profiler: implement general exclusion
* profiler: include onload/offload efforts in mpse
* profiler: refactor
* profiler: split out paf from stream_tcp
* profiler: track DAQ message receives and finalizes
* snort: remove out-of-date Snort 2 version from -V
* stream: add convenient method for flow deletion
* stream_tcp: Add no-ack policy to handle flows that have no ACKs for data
* stream_tcp: fix non-deep detect profile exclusion
* talos.lua: various fixes for command line usage

2019-06-19: build 257

* analyzer: publish finalize packet event before calling finalize_message
* appid: Protocol based detection for non-TCP non-UDP traffic
* appid: support for dynamic host cache lookup-based app detection
* build: Fix unused parameter warnings in unit tests
* check: Fix missing semicolons on CHECK calls
* detection: adding pegcounts for fallback, offload failures
* detection: add peg for onload wait conditions
* detection: fix check for disabled rules
* detection: fix creation of service map to use ips policy id
* detection: on PDUs search TCP/UDP portgroups even when user_mode services exist
* doc: Remove perpetually out-of-date copy of LibDAQ's README
* doc: Update documentation to reflect post-DAQng reality
* flow: check if flow is actually deleted before updating memstats
* flow: Implement storing and importing HA data via DAQ IOCTLs
* http_inspect: stop clearing http data snapshots from ips contexts on flow deletion
* http_inspect/stream: accelerated blocking
* http_inspect: test tool enhancement
* icmp4: verify checksum before the type validation
* ips_options: add relative parameter to so option
* perf_mon: removed flow_ip_handler from PerfMonitor
* regex: fix repeated search offset
* rna: Fixing doc build failure due to asciidoc format issue
* rna: Implementing event-driven RNA inspections
* rna: Introducing barebone RNA module and inspector
* rna: Renaming peg counts and adding a warning when config changes
* smtp: Fix handle_header_line and normalize_data unit tests
* smtp: pass packet pointer instead of nullptr to SMTP_CopyToAltBuffer
* stream: Do not validate timestamp until peer timestamp is set
* stream_ip: Checking null inspector while updating session

2019-05-22: build 256

* DAQng: Port Snort and its DAQ modules to DAQ3
  - Massive refactoring of the Analyzer thread
  - Handle multiple offloaded wire packets
  - Port hext and file DAQ modules to DAQng
  - Reimplement the RETRY verdict internal to Snort
  - Revamp skip-n/exit-after-n/pause-after-n handling
  - Update lua tweaks with new DAQ configuration format
  - Update sfdaq unit tests for DAQng
  - Update snort2lua to convert to new DAQ configuration
* filters: add peg count for when the thd_runtime XHash table gets full
* filters: make thd_runtime and rf_hash thread local and allocate them from thread init
  rather than from Module::end()
* http_inspect: fix status_code_num bug in HttpMsgHeader::update_flow() that leads to
  assert on input.length()>0 in norm_decimal_integer
* main: Fix File Descriptor leaks
* main: Include analyzer.h in snort.c
* packet_io: Refactor the Trough a bit
* perf_mon: Fixed time stamp and memory leak issue
  - Add real timestamp to empty perf_stats data
  - Updated dbus default subscription code and perf_mon event subscirption code
    to resolve memory leak and invalid event subscription from reloading
  - Moved flow_ip_tracker to thread local
* perf_monitor: Fixing heap-use-after-free after reload failure
* port_scan: Change minimum memcap value to 1024 to avoid divide by zero crash
* rule_state: change enable values "true" / "false" to "yes" / "no"
* snort2lua: Remove sticky buffer duplicates
* stream: disable inspection of flow on reset

2019-05-03: build 255

* ips: add includer for better relative path support
* module_manager: Fix potential null deref in module parameter dumping

2019-04-26: build 254

* analyzer: Print pause indicator from analyzer threads
* appid: remove inspector reference from detectors
* build: Remove perpetually stale reference to lua_plugffi.h
* build: remove unused cruft; clean up KMap
* config: replace working dir overrides with --include-path
* context: only clear ids_in_use in dtor
* file_type: remove redundant error message
* log_pcap, packet_capture: Don't try to use a DAQ pkthdr as a PCAP pkthdr
* Lua: update tweaks per latest include changes
* main: Use epoll (for linux systems) instead of select to get rid of limit on fd-set-size and for
  time efficiency
* snort2lua: fix histogram option change comment
* snort2lua: Integer parameter range check
* stream_tcp: Try to work with a cleaner Packet when purging at shutdown
* test: remove cruft

2019-04-17: build 253

* build: delete unused code called out by cppcheck
* doc: remove mention of obsolete LUA_PATH, SNORT_LUA_PATH, and required snort_config library
* flow_cache: Pruning one stream when excess pruning skips even if max_sessions is reached
* ftp_server: fix normalization and PDU parsing issues
* helpers: directory: use readdir instead of readdir_r
* Lua: apply the necessary builtin defaults from one place
* Lua: internalize snort_config.lua dependency
* Lua: build-time stringify Lua files for use as C++ variables
* Lua: remove dependency on SNORT_LUA_PATH
* mime: fix decompression for multiple files
* parser: update include file handling
* parser: fix defaults for alerts.order and network.checksum_eval

2019-04-10: build 252

* appid: Fix NetworkSet compilation on big-endian systems
* appid: Reduce variable scope in service_mdns
* appid: Reduce variable scope in service_rpc
* codecs/ipv4: Use struct in_addr when calling inet_ntop()
* dce_rpc: Fix const cast warnings in dce_smb2
* detection: Don't send zero size searches to the regex offloader
  If a batch search request had nothing in it to be
  searched for there is no purpose in sending it to
  the offloader
* detection: Ensure offload search engine started with appropriate regex offloader
  If the offload_search_method is not specified then by
  default it will be the same as the normal search_method
  If this search method is an async mpse it needs started
  using the MpseRegexOffload offloader otherwise it needs
  started using the ThreadRegexOffload offloader
* file_api: add extract filename to FileFlow from mime header
* file_api: Add timer to limit how long we want for pending file lookup
* file_api: If configured, reset session when lookup times out
* file_api: Make expiration timers more granular
* file_api: use more generic form of timercmp and fix timersub call
* file_api: use timersub_ms, updates to packettracer logs
* flow: add the override keyword to some member function to keep cppcheck happy
* flow: add test to check that a handler is not getting stash events that it's not listening to
* flow: stash publish event
* flow: unit test for stash publish
* ftp_telnet: Fix potential NULL pointer arithmetic in check_ftp()
* ftp_telnet: Fix val-never-used warning in DoNextFormat()
* http_inspect: Fix val-never-used warning in check_oversize_dir()
* http_inspect: Give HttpTestInput a destructor to clean up its file handle
* log: Fix potential NULL pointer arithmetic warning in log_text
* mpse: Adding performance profiling stats to Mpse batch search
  The Mpse batch search function does not have any
  performance profiling so this function is now wrapped
  to facilitate the addition of performance stats
* normalize: Remove redundant check during configuration
* offload: simplify zero byte bypass
* offload: Framework changes to support polling for completed
  batch searches
  When a batch search is issued, currently we poll to
  determine if that batch has completed its search
  This change facilitates polling to return any batch
  that has completed its search
* packet_io: Changes to allow daq retries to work properly
* packet_io: add entry for retry in act_str due to re-ordering
* packet_io: re-order ACT_RETRY to be before ACT_DROP
* packet_tracer: Pass filename string parameter by reference
* perf_monitor: Pass ModuleConfig string parameter by reference
* port_scan: Reduce variable scope in configuration
* rule_state: rule_state: do not require rules in all policies
* rules: remove cruft from tree nodes
* sfip: Reduce variable scopes in sf_ipvar
* sfip: Switch test debug flag to a cpp macro
* sfrt: Reduce variable scope in _dir_remove_less_specific()
* sip: Give SipSplitterUT a proper copy constructor
* snort2lua: Adding support for appid tp_config_path conversion
* snort2lua: Convert rawbytes to raw_data sticky buffer
* so rules: fixup shutdown sequencing
* so rules: make plain stubs same as protected
* so rules: use stub strictly as a key
* stream: set retransmit flag
* stream_ip: Fix sign comparison and val-never-used issues in defrag
* stream_tcp: Fix shadowed variable when profiling deeply
* u2spewfoo: update due to re-ording of retry action

2019-03-31: build 251

* ActionManager: actions are tracked per packet for accurate packet suspension
* DetectionEngine: make onload safe for reentrance
* DetectionEngine: stall when out of contexts
* Flow: is_offloaded is now is_suspended
* IpsContext: removed useless SUSPENDED_OFFLOAD state
* Mpse: Addition and use of offload search method/engine
* Mpse: fixed build warning about constness of get_pattern_count
* MpseBatch: refactor into separate files
* Packet: fixed thread safety in onload flag checks
* RegexOffload: onload whatever is ready
* RegexOffload: refactor into mode-specific subclasses
* appid: Fix for FTP detection with multiline server response split across multiple packets
* appid: add unit test to make sure the AppIdServiceStateKey::operator<() is OK and modify
  existing service cache memcap test to alternate ipv4 and ipv6 addresses
* appid: change the service queue to store map iterators rather than the actual keys, as
  (a) map iterators are stable and (b) sizeof(map::iterator)=8 while sizeof(key)=28
* appid: compute the size of the memory used for a service cache entry only once, as it is
  constant, and make it global
* appid: fix AppIdServiceStateKey::operator<()
* appid: fix client discovery to only check on the first data packet
* appid: fix comment in client_discovery.cc
* appid: fix double free in service_state_queue and address reviewers comments
* appid: fixup profiling
* appid: get rid of the map::find() in MapList::add(), just try to emplace directly
* appid: implement service cache touch(). Must figure out where to call it from
* appid: implement service discovery state queue to honor memcap
* appid: introduce min memcap of 1024 with a default of 1Mb and refactor
  AppIdServiceState::remove() to accept a ServiceCache_t::iterator rather than ip, proto,
  port and decrypted
* appid: introduce the do_touch flag to the add/get functions and call those functions with
  the appropriate flag
* appid: keep cppcheck happy
* appid: more cppcheck clean-up
* appid: pass HostPortKey by reference in HostPortKey::operator<()
* appid: put the service_state_cache and the service_state_queue into a class in its own
  right and refactor the code
* appid: remove forgotten WhereMacro
* appid: rename some global variables in http_url_patterns_test.cc to suppress cppcheck messages
* appid: replace the custom AppIdServiceCacheKey::operator< with memcmp in both service_state.h
  and host_port_app_cache.cc
* appid: return void in ClientDiscovery::exec_client_detectors() and set client_disco_state to
  FINISHED in all cases except when the client validate returns APPID_INPROCESS
* appid: set a range for app_stats_period parameter
* appid: skip empty detectors
* appid: the service queue should be of type AppIdServiceStateKey
* appid: unit test for service cache and call the touch function
* appid: untabify service_state.h and test/service_state_test.cc
* appid: update unit test file
* binder: Reset flow gadget and protocol ID on failed rebinding
* binder: store user set ips policy id from lua
* build: Add better support for libiconv on systems with iconv-providing libc
* build: fix always true warning
* build: fix constness warnings
* build: fix cppcheck warnings for file_connector, tcp_connector, ports, snort2lua, and
  piglet_plugins,
* build: fix override warning
* catch: Update to Catch v2.7.0
* cd_tcp: some light refactoring
* conf: remove obscure and slow automatic iface var assignments; use Lua instead
* config: Use basename_r() function for FreeBSD versions < 12.0.0
* control: Avoid deleting objects on write failures so that they get deleted from main thread
  during read polling
* copyright: update year to 2019
* cppcheck: fix some basic warnings
* dce_rpc: Added support to handle smb header compounding
* dce_rpc: Limiting each signature alert to once per session using 'limit_alerts' config
* dce_rpc: fix cppcheck warnings
* dce_rpc: fix style warning non-boolean returned
* decompress: add zip file decompression
* detection, snort2lua: added global rule state options for legacy conversions
* detection: Add search batching infrastructure
* detection: allow suspension of entire chains of contexts
* detection: fixed incorrect log messages
* detection: only swap offload configs when they change
* detection: split fast pattern processing when using context suspension
* doc: add a section for reload limitations
* doc: update default manuals
* doc: update reload limitations - adding/removing stream_*
* file: fixed data race at shutdown
* file_api: Added nullptr checking to prevent segfaults when file mempool is not configured
* file_api: call FileContext::set_file_name() from FileFlows::set_file_name with
  fname = nullptr, in order to generate file event
* file_api: fail the reload if max_files_cache is changed  or if capture was initially enabled
  and capture_memcap or capture_block_size change
* file_api: fix policy lookup
* file_capture: refactor max size handling
* filters: call get_ips_policy instead of get_network_policy when building the key for
  rate filter
* flow: Added a support to store generic objects in a stash
* flow: support for flow stash - allows storage of integers and strings
* flow_control: remove unused session flag
* fp_detect: suspend instead of onload if fp_local can't occur yet
* hash: Added lru_cache_shared.h to HASH_INCLUDES
* hash: Moved list_iter assignment inside to avoid improper memory access in LruCacheShared
* http_inspect: disable reg test assertion until interface with stream_tcp is updated
* http_inspect: patch around buffer ownership confusion
* ips_context: minimize iterations to clear data
* ips_options: implement FileTypeOption::hash() and FileTypeOption::operator==(), inherited
  from IpsOption, using the types bitset array, in order to distinguish between different
  file type options
* loggers: add alert_talos, use in talos tweak
* loggers: alert_talos: fix copyright, author, unneeded check
* loggers: alert_talos: fix copyright, warnings
* loggers: alert_talos: fix cppcheck error
* loggers: alert_talos: fix include order
* loggers: alert_talos: fix memory leak
* loggers: workaround for cppcheck's false warning
* lua: make RTF file magic more generic
* main: log message when all pthreads started (REG_TEST only)
* main: shell commands and signals executed only after snort finish startup
* memory: Use only one variable to keep track of allocated and deallocated memory
* memory: add configurable L3/L4 specific weights for better estimation against cap
* memory: add size_of to various FlowData subclasses
* memory: apply fudge factor to tracking to better align with RSS
* memory: basic flow data allocation tracking
* memory: basic flow pruning
* memory: beware the perf_monitor, for she stealeth your numbers
* memory: do not re-enter the pruner
* memory: fix re-entry check
* memory: increase default tcp cache cap weight; fix default values
* memory: initial preemptive pruning based on flow data
* memory: refactor stats
* memory: remove overloading manager to make way for new implementation
* memory: remove useless thread local
* memory: require subclass implementation of FlowData::size_of()
* memory: track session allocations
* mime: add file decompression
* misc: fixed warnings generated from latest gcc
* packet tracer: initialize sf_ip structs
* policy: allow an empty policy be set explicitly
  assigned to it
* policy: Rename TRUE/FALSE to ENABLE/DISABLED
* port_scan: Fail reload if memcap changed
* profile: convert remaining layer 2 or greater profile scopes to the deep, dark underbelly
* profiler: add quick exit if not configured to minimize overhead
* profiler: add quick exit if not configured to minimize overhead (rule times)
* protocols: fix style warning non-boolean value returned
* react: sending reset to server only
* regex_offload: fix stats for thread
* reload: differentiate between restart required and bad config
* reload: fail reload if stream is in the original config and stream_* is added/removed
* reload: prompt reload failure and require restart when stream cache were changed
* reload: send reload completed message to control channel instead of logging it
* rule eval: ensure leaf children are properly counted
* rule_state: add rtn but disable if block is set on non-inline deployment
* rule_state: added default rule state to ips policy
* rule_state: added per-ips-policy rule states
* rules: do not preallocate actions
* safec: Update to work with modern versions of LibSafeC
* sfip: add a FIXIT for checking that the current implementation of _is_lesser(), which only
  compares same-family ips is OK
* sip: update sip options to use has_tcp_data instead of is_tcp
* snort2lua: Create dev_notes.txt for sticky buffers
* snort2lua: adding when.role for specific inspectors
* snort2lua: change the -l short option to --dont-convert-max-sessions
* snort2lua: combining multiple zone in one binder rule
* snort2lua: comment gid 147 file rules
* snort2lua: convert file_capture config options
* snort2lua: do generate the tcp_cache instance even when we don't convert tcp_max to
  max_sessions
* snort2lua: do not translate max_sessions from snort.conf to snort.lua
* snort2lua: fix pcre option issues
* snort2lua: fix sticky buffer duplication
* snort2lua: fixed duplication of split_any_any from config: detection
* snort2lua: introduce command line option -l to suppress conversion of max_tcp, max_udp,
  max_icmp and max_ip to max_sessions
* snort2lua: move obfuscate_pii to the ips table from the output table
* snort_config: Add a setter for setting run_flags and set it to TRACK_ON_SYN for hs_timeout
  config
* ssl: Count calls to disable_content for ssl sessions
* stream: Change StreamSplitter::scan to take a Packet instead of a Flow
* stream: Pass Packet in flush_pdu_* -> paf_eval -> paf_callback chain
* stream: fixed ignore_flow segfault bug caused by allocating generic flow data instead of
  inspector specific flow data
* stream: log StreamBase::config in StreamBase::show()
* stream: purge remaining flows before shutdown counts
* stream_tcp: add track_only to disable reassembly
* stream_tcp: consolidate segment node and data
* stream_tcp: disambiguate seglist trace
* stream_tcp: do not purge partially acked segment
* stream_tcp: fix up stream order flags
* stream_tcp: fixup allocation tracking for overlapped segments
* stream_tcp: implement reserve seglist
* stream_tcp: initialize priv_ptr for pdus
* stream_tcp: patch around premature application of delayed actions that yoink the seglist
* stream_tcp: remove seglist node cruft
* stream_tcp: reset paf segment when switching splitters
* stream_tcp: simplify paf init
* stream_tcp: support unidirectional flushing similar to Snort 2
* stream_tcp: tweak PAF scanning
* stream_tcp: tweak ips mode flushing
* stream_udp: ensure all flows are cleared fully
* time: Adding timersub_ms function to return timersub in milliseconds

2018-12-06: build 250

* actions: Fix incorrect order of IPS reject unreachable codes and adding forward option
* active: added peg count for injects
* active, detection: active state is tied to specific packet, not thread
* appid: Don't build unit test components without ENABLE_UNIT_TESTS
* appid: Fix heap overflow issue for a fuzzed pcap
* build: accept generator names with spaces in configure_cmake.sh
* build: clean up additional warnings
* build: fix come cppcheck warnings
* build: fix some int format specifiers
* build: fix some int type conversion warnings
* build: reduce variable scope to address warnings
* detection: enable offloading non-pdu packets
* detection, stream: fixed assuming packets were offloaded when previous packets on flow have
  been offloaded
* file_api: choose whether to get file config from current config or staged one
* file: fail the reload if capture is enabled for the first time
* framework: Clone databus to new config during module reload
* loggers: Use thread safe strerror_r() instead of strerror()
* main: support resume(n) command
* managers: update action manager to support reload
* module_manager: Fix configuring module parameter defaults when modules have list parameters
* parameter: add max31, max32, and max53 for int upper bounds
* parameter: add maxSZ upper bound for int sizes
* parameter: build out validation unit tests
* parameter: clean up some signed/unsigned mismatches
* parameter: clean up upper bounds
* parameter: remove arbitrary one day limit on timers
* parameter: remove ineffective -1 from pcre_match_limit*
* parameter: reorgranize for unit tests
* parameter: use bool instead of int for bools
* parameter: use consistent default port ranges
* perf_monitor: Actually allow building perf_monitor as a dynamic plugin
* perf_monitor: fix benign parameter errors
* perf_monitor: fixed fbs schema generation when not building with DEBUG
* protocols: add vlan_idx field to Packet struct and handle multiple vlan type ids;
  Thanks to ymansour for reporting the issue
* regex worker: removed assert that didn't handle locks cleanly
* reputation: Fix iterations of layers for different nested_ip configs and show the
  blacklisted IP in events
* sip: Added sanity check for buffer boundary while parsing a sip message
* snort2lua: add code to output control = forward under the reject module
* snort2lua: Fix compiler warning for catching exceptions by value
* snort2lua: Fix pcre H and P option conversions for sip
* snort: add --help-limits to output max* values
* snort: Default to a snaplen of 1518
* snort: fix command line parameters to support setting in Lua;
  Thanks to Meridoff <oagvozd@gmail.com> for reporting the issue
* snort: remove obsolete and inadequate -W option;
  Thanks to Jaime González <jaimeglz1952@gmail.com> for reporting the issue
* snort: terminate gracefully upon DAQ start failure;
  Thanks to Jaime González <jaimeglz1952@gmail.com> for reporting the issue
* so rules: add robust stub parsing
* stream: fixed stream_base flow peg count sum_stats bug
* stream tcp: fixed applying post-inspection operations to wrong rebuilt packet
* stream tcp: fixed sequence overlap handling when working with empty seglist
* style: clean up comment to reduce spelling exceptions
* thread: No more breaks for pigs (union busting)
* tools: Install appid-detector-builder.sh with the other tools;
  Thanks to Jonathan McDowell <noodles-github@earth.li> for reporting the issue

2018-11-07: build 249

* appid: Fixing profiler data race and registration issues
* appid: make third party appid stats configurable
* appid: Remove detector flows from the list for faulty lua detectors
* build: remove dead code
* build: support dynamic imap, pop, and smtp
* comments: additional cleanup
* comments: delete obsolete comments
* comments: fixup format, spelling, priority, etc
* comments: remove XXX and convert to FIXIT where appropriate
* connectors: Fix TCP connector unit test compilation on Alpine Linux (musl)
* cppcheck: cleanup some warnings
* dcerpc: fixed build warning with struct packing
* dcerpc: fixed setting endianness on one packet and checking on another
* detection : add function to clear ips_id from unit tests
* detectionengine: Only clear inspector data after offloads have completed
* detection/http_inspect: Save a snapshot HTTP buffers in the IPS context to support offload
  of HTTP flows
* doc: Adding performance consideration for developers
* file_api: revert deleting gid 146 so existing 146 rulesets dont attempt empty rule eval
* fixits: prioritize for RC
* flow: fixed build warning
* flow: track multiple offloads
* fp_detect: onload before running local to ensure event ordering
* framework: replace the newly introduced loop to reset the reload_type flags with the
  existing Inspector::update_policy function
* framework: set the reload_type flags to RELOAD_TYPE_NONE at the end of reload, in
  anticipation of future reloads
* host_tracker: fixed uppcase IP param issue
* http2_inspect: Change http2 GID from 219 to 121
* ips_flowbits: move static structures to snort config
* main: initialize shell_map and other maps in PolicyMap::clone()
* main: size analyzer notification ring appropriately
* manual: fix some typos
* mime: made the mime hdr info and current search thread local
* mime: move the decode buffer used by mime attachments to mime context data
* packet_tracer: can't emplace vector<bool> until c++14
* parser: bad filename during reload is not a fatal error
* perfmon: fix issue for report correct stats after passing -n pkts
* perf_monitor: trackers keep copy of the relevant config items from the inspector
* reload: fixed smtp seg fault when reload failed
* reputation: delete old conf before allocating a new one in ReputationModule::begin() if
  conf not null
* rule_state: indicate list format
* search_tool: include bytes searched in pattern match stats
* search_tool: validate ac_full and ac_bnfa wrt search and search_all
* snort2lua: Add support for enable/disable iprep logging using suppress mechanism
* snort2lua: Avoid returning reference of local variable
* snort2lua: comment out deleted gid 146 rules
* snort2lua: Enable address_anomaly_detection during snort2lua and fixed missing string
  sanity checks
* snort2lua: fixed paf_max to stream_tcp.max_pdu convertion
* snort2lua: tweak for style consistency
* snort: add --rule-path to load rules from all files under given dir
* snort: Code refactoring - replacing push_back/insert by emplace_back/emplace, keeping
  reputation_id in flow instead of flow_data, and appid code improvements
* source: fix some typos
* source: minor refactoring
* spell: fix typo
* stream, detection, flow: don't force onloads between pdus unless absolutey necessary
* stream: fixed build warning
* stream: only delete flows after all onloads
* stream tcp: don't delete flow data on rst, let session close handle it
* textlog: removed unused TextLog_Tell function
* thread_idle: call timeout flows with packet time for pcap replay
* utils: fixed deprecation build warning on register keyword

2018-09-26: build 248

* appid: adding detector builder and fixing stats to recognize custom appid;
  Thanks to Wang Jun <traceflight@outlook.com> for reporting the issue
* appid: fixing ubuntu check tests
* appid: fix valgrind issues in SIP event handler
* appid: FreeBSD unit-test fix
* appid: supporting pub-sub mechanism for app changes
* build: add libnsl and libsocket to Snort for Solaris builds
* build: fall back on TI-RPC if no built-in RPC DB is found
* build: introduce a more robust check for GNU strerror_r
* daqs: include unistd.h directly for better cross-platform compatibility
* dce_rpc: add DCE2_CO_REM_FRAG_LEN_LT_SIZE (133:31) to the TCP rule map
* dce_rpc: add DCE2_SMB_NB_LT_COM (133:11) to the SMB rule map
* detection: added post-onload callbacks
* detection: allocate ips context data using hard coded max_ips_id == 32
* detection: don't use s_switcher to get file data
* detection: run active actions at onload
* detection: use packet to reference context
* file_api: fix off-by-one bug that was hurting performance
* file_api: move the check on REJECT or BLOCK inside an upper if clause for performance reasons
* file_api: set disable flow inspection as soon as the verdict is REJECT
* file_api: treat a BLOCK verdict the same as a REJECT verdict, for good measure
* http_inspect: split and inspect immediately upon reaching depth
* latency: added cleanup for RegexOffload threads
* lua: changing default FTP EPSV string format
* main: pause-after-n support
* managers: handle tinit for inspectors added during reload
* managers: if a plugin doesn't have tinit, still mark it as initialized
* reputation: early return on parsing error causing uninitialized id
* reputation: fix SI doesn't block traffic if Any Zone is specified

2018-08-27: build 247 - Beta

* appid: change map to unordered map
* appid: declare SMTPS early in STARTTLS state on success response code
* appid: fix data-race issues from ips_appid_option and improve app_name search
* detection: avoid repeating detection by always doing non-fast-pattern rules immediately
  (applies to experimental offload only)
* docs: update default html, pdf, and text user manuals
* reputation: reevaluate current flows upon reload
* stream_tcp: avoid duplicating split sement data
* build: removing use of u_char and u_short macros (github #53)

2018-08-13: build 246

* active: Add an upper limit of 255 to min_interval
* appid: Avoid snort crash upon lua file errors
* appid: Fixes for TNS, eDonkey, and debug logs in Lua detectors
* appid: Single lua-state per thread
* appid: code clean-up
* appid: create developer notes document
* appid: make the code compatible with the latest version of snort2
* appid: refactor detector initialization
* appid: fix multithreading issues (data races) from app_forecast
* appid: many other updates
* binder: Make two passes at binder rules - one for policy IDs and then everything else
* binder: Refactor binder as a passive, event-driven inspector
* byte_test: update operator parsing, remove dead code
* catch: Update to Catch v2.2.3
* codecs: Handle raw IP packets in Snort proper
* codecs: fix dynamic build of root codecs
* decode: alternate checksum calculation to improve runtime performance
* detection: don't offload when 0 threads are configured
* detection: save the ropts used for dce rule options in ips context to support offload
* detection: various bug fixes for offload emulation
* doc: Update regarding the build issue with --enable-tcmalloc flag and known workarounds
* doc: added active response section to user manual
* doc: corrections to tutorial section
* doc: update known problems
* events: remove manager cruft
* file_id: fix uninitialized
* file_magic: Update file_magic.lua to cover all file types and versions
* framework: Enable dynamic building of ips_{pcre,regex,sd_pattern} + Hyperscan MPSE
* framework: Scratch handlers for SnortState
* framework: fixed adding probe to wrong SnortConfig
* http_inspect: URI normalization added to dev_notes
* http_inspect: add perfmon to splitter
* http_inspect: bug fix and cleanup
* http_inspect: memory reduction and misc cleanup
* http_inspect: renumbered events to avoid current and future conflicts with Snort 2.X
* inspector: Rename ::update() to ::remove_inspector_binding() to better reflect what it does
* ips: Remove unused IPS module stats
* ips_fragbits: Removed dead code
* packet_tracer: Report user policy IDs and add network policy
* parser: reset parse error count before reload to avoid confusion
* perf_monitor: fix for reload
* perf_monitor: format error in dev_notes
* policy: Add the ability to set network policy based on user-specified ID
* policy: Export querying policies by user ID and setting runtime policies
* profiler: Don't clobber max entry count when recursing
* reload: do not set policies for incremental reload case
* reload: set policies upon swap to avoid dangling pointers when idle
* reputation: make sure reputation inspector is called in default policy
* reputation: support reload module
* sfip: if ips_policy doesn't exist, allow for ipvar parsing without vartable
* sip: Ported sip-splitter implementation from snort2
* snort.lua: add inline tweaks
* snort.lua: add talos defaults
* snort.lua: fix tweaks path;
  Thanks to brastult@cisco.com for reporting the issue
* snort.lua: fix community rules filename;
  Thanks to mike@flyn.org for reporting the issue
* snort2lua: Handle sidechannel config
* snort2lua: add conversion for shared memory
* snort2lua: added missing keyword to nap parsing
* snort2lua: don't try to index into empty lines
* snort2lua: fixed nap ip parsing
* snort2lua: merge multiple nap rules with the same id
* snort2lua: translate file_type rule option
* snort: match delete[] with new[]
* snort: wrap snort SO_PUBLIC symbols in the snort namespace
* ssh: added test code
* stream_ip: match delete[] with new[]; don't create zero length trackers
* stream_tcp: 86 r_nxt_ack as tracker state for next rx seq, use rcv_nxt instead
* stream_tcp: back out fin handling changes for bug not relevant to snort3
* tcp_connector_test: fixed version-sensitive build problem

2018-05-21: build 245

* CodecManager: removed unused code
* DataBus: fixed creating DataHandler when one doesn't exist
* Debug messages: cleanup for service inspectors.  New traces for detection, stream
* Debug: Final debug messages cleanup, removal of macros from snort_debug
* Ipv4Codec: removed random ip id pool and replaced randoms on demand
* PacketManager: moved encode storage to heap
* PerfMonitor: fixed subscribing to flow events multiple times
* ProtoRef: Converge on single name for SnortProtocolId. Fix threading problems
* Reset: Always queue reject and test packet type in RejectAction::exec
* SFDAQModule: moved daq stats here. fixed stats not being output from perfmon
* Snort2lua: Add ftp_data to multiple files when needed, once per file
* Snort2lua: Translate ftp_server relative to default configurations
* Snort: moved s_data to heap
* active: Enable when max_responses is enabled
* alert: moved alert json. unixsock out from extra to snort3
* appid: Add AppID debug command
* appid: Enable Third-Party Code for Packet Processing
* appid: Fix bug where Service and Application ID's set to port number instead of service appid
* appid: Fixing service discovery states
* appid: Only import dynamic detector pegcounts once
* appid: Refactor debug command
* appid: Refactor debug command, use SfIp, and fix non-Linux compilation
* appid: Third party integration support
* appid: appid session unit test changes
* appid: change metadata buffers from std::string to pointers, to avoid extra copying
* appid: clean-up code for performance and implement is_tp_processing_done()
* appid: create referer object only for non-null string
* appid: do not inspect out-of-order flows, ignore zero-payload packets for client/service
  discovery
* appid: fix memory leak in appid_http_event_test and warning in appid_http_session.cc
* appid: fix segfault due to dereferencing null host pointer
* appid: fix tabs and indentation
* appid: fixed http fields, referer payload and appid debug
* appid: make tp_attribute_data more localized, so we only allocate/deallocate it if needed
* appid: moved HttpFieldIds to appid_http_session
* appid: peg count / dynamic peg count update.  Split peg counts into the ones known at
  compile time and dynamic ones.  Update stats , module manager and module to support
  dumping dynamic stats
* appid: report when third party appid is done inspecting
* appid: sip: moved pattern thread local to class instance
* base64_decode: moved buffer storage to regular heap
* binder: Fix UBSAN invalid value type runtime error
* build: 244
* build: Add --enable-ub-sanitizer option for undefined behavior sanitizer
* build: Add some header includes for FreeBSD
* build: Clean up CMake string APPENDing for configure options
* build: Clean up HAVE_* definition checks
* build: Define NDEBUG if debugging is not enabled
* build: Fix building unit tests on FreeBSD
* build: Modernize code with =default for special member functions
* build: Modernize code with virtual/override/final cleanups
* build: Remove bashisms from most shell scripts
* build: add cmake configure switches for NO_PROFILER, NO_MEM_MGR and DEEP_PROFILING
* build: add disable-docs to disable doc build
* build: fix various drops const qualifier cases
* build: fix various warnings:
* build: propogate snort3 tsc build option to the extra build system
* byte_extract: fix cursor update
* byte_jump: fix from_beginning
* byte_math: allow rvalue == 0 except for division
* catch: Update to Catch v2.2.1
* clock: Allow use of ARM64 CNTVCT_EL0 register for timing (#46);
  Thanks to j.mcdowell@titan-ic.com for the patch
* clock: use uint64_t with tsc clock instead of std::chrono for performance
* cmake: Add --enable-appid-third-party to configure_cmake.sh
* cmake: Add support for building with tcmalloc
* cmake: Rework FindPCAP logic and ignore SFBPF
* cmake: fixed checks for functions
* cmake: update for iconv
* codecs: add config option to detection to enable check and alert for address anomalies
* daq_hext: Make IpAddr() static to fix compiler warning
* dce_co_process_ctx_id needs to update its caller's (DCE2_CoCtxReq) frag_ptr as it is
  called in a loop in order to parse each dce/rpc ctx item, otherwise it ends up parsing
  the same ctx item over and over
* dce_rpc: fix parsing of dce/rpc ctx items
* dce_rpc: pass frag_ptr by reference
* debug: Remove debug messages from appid, arp_spoof, and perf_monitor
* debug: Remove debug messages from detection and ips_options
* debug: Remove debug messages from stream
* decompress/file_decomp_pdf.cc: implicit fallthrough
* detect: moving thread locals identified to ips context
* detection: fixed uninitialized MpseStash
* doc: add doc for module trace
* encoders: fixed off-by-one error in underlying buffer handling
* extra: Port some CMake options from Snort prime
* extra: splitted extra out to snort3_extra repo
* file_api: combine file cache for file resume and partial file processing
* file_connector: Fix address-of-packed-member compiler warnings
* file_decomp_pdf.cc: unreachable code return
* file_type: Require strings instead of integers for types. Handle versions
* flow: SO_PUBLIC FlowKey
* framework: align PktType and proto bits
* framework: remove bogus PktType for ARP and just use proto bits instead
* ftp_server: Added Flow::set_service and fixed FtpDataFlowData::handled_expected
* ftp_server: Added ability get TCP options length from TcpStreamSession
* ftp_server: Added accessors to Stream so TcpStreamSession can be private
* ftp_server: Base last_seg_size off of MSS
* ftp_server: Provide FLOW_SERVICE_CHANGE pub/sub event
* ftp_server: ftp_server requires that ftp_client and ftp_data be configured
* hashfcn: Fix UBSAN integer overflow runtime error
* hashfcn: Fix UBSAN left shift of negative value runtime error
* http_inspect: broken chunk performance improvement
* http_inspect: bugfix and new alert for gzip underrun
* http_inspect: embedded white space in Content-Length
* http_inspect: handling of run-to-connection-close bodies beyond depth
* http_inspect: know more Content-Encodings by name
* http_inspect: patch around regression failures until a permanent solution is implemented
* http_inspect: performance enhancements for file processing beyond detection depth
* ip: replaced REG_TEST with -H option for ipv4 codec fixed seed
* ips_byte_jump: Fix UBSAN left shift of negative value runtime error
* ips_byte_math: Fix UBSAN left shift of negative value runtime error
* ips_flags: remove dead code
* javascript: moved decode buffer to stack
* memory: disable with -DNO_MEM_MGR
* memory_manager.cc: dangling references
* packet_capture, cmake: Remove SFBPF dependencies
* packet_capture: adding analyzer command to initialize dump file
* packet_tracer: Fix compiler warning when compiling with NDEBUG
* packet_tracer: Modularize and add constraint-based shell enablement
* parameter: Fix UBSAN shift exponent is too large for 32-bit type runtime error
* parser: allow arbitrary rule gids
* pop, imap, and smtp: changes to MIME configuration parameters
* port_scan: include open ports with alerts instead of separate
* profile: disable with -DNO_PROFILER
* profiler: add deep profiler option
* reload: enabled reloading ips_actions; added parse error check for reloading
* repuation: remove the limit for zone id
* reputation: add zone support
* search_engine: revert default detect_raw_tcp to false
* service inspectors: debug cleanup
* sfip: A version of set() which automatically determines the family
* sfip: removed ntoa. use ntop(SfIpString) instead
* snort2lua: Add reject action when active responses is enabled
* snort2lua: conversion of gid 120 to 119
* snort2lua: enable reject action when firewall is enabled
* snort: -r- will read packets from stdin
* spell check: fix memeory and indicies typos
* steam_tcp: change singleton names from linux to new_linux to avoid spurious collisions
  with defines
* stream ip: refactored to use MemoryManager allocators
* stream: assume gid 135 so those rules are handled as standard builtins
* stream: be selective about flow creation for scans
* stream: refactor flow control for new PktTypes
* stream: remove usused ignore_any_rules from tcp and udp
* stream: respect tcp require_3whs
* stream: warning: potential memory leaks
* stream_tcp: refactor tcp normalizer and reassembler to eliminate dynamic heap allocations
  per flow
* stream_tcp: switch to splitter max
* stream_tcp: tweak seglist cursor handling
* target_based: 100% coverage on snort_protocols.cc
* target_based: unit tests for ProtocolReference class
* tcp codec: count bad ip6 checksums correctly;
  Thanks to j.mcdowell@titan-ic.com for reporting the issue
* tcp: allow data  handlding for packet with invalid ack
* time: initialize Stopwatch::start_time member variable to 0 ticks when TSC clock is enabled
* trace: add traces for deleted debug messages
* wizard: Fix UBSAN out-of-bounds access runtime error
* zhash: cleanup cruftiness

2018-03-15: build 244

* appid: unit-tests for http detector plugins
* build: address compiler warnings, spell check and static analyzer issues
* build: extirpate autotools usage
* build: fix compilation issue on FreeBSD with extra
* byte_jump: updated byte_jump post_offset option to support variable
* cmake: update CMake config to use GNUInstallDirs and match automake
* daq: hext DAQ can generate start of flow and end of flow meta events
* doc: add documentation for ftp telnet
* doc: fix including config_changes.txt when ruby is not present
* doc: update ftp time format link
* doc: updates for HTTP/2
* http_inspect: handle white space before chunk length
* inspectors: probes run regardless of active policy
* logger: update Hext Logger to subscribe and log DAQ Meta Packets
* main: reload hosts while reloading config
* memory: override C++14 delete operators as well
* packet tracer: added ability to direct logging to file
* perf_monitor: fixed flow_ip outputting erroneous values
* perf_monitor: query modules for stats only after they have all loaded
* snort: --rule-to-text [<delim>] raw string output
* snort: allow colon separated directories for --daq-dir
* snort: wrap SO_PUBLIC APIs (classes, functions exported public from snort) in the 'snort'
  namespace

2018-02-12: build 243

* build: enable gdb debugging info by default
* build: fix cppcheck warnings
* build: fix static analysis issue
* comments: fix 6isco typos
* copyright: update year to 2018
* detection: use detection limit (alt_dsize)
* detection: trace fast pattern searches with 0x20
* detection: do not change search_engine.inspect_stream_inserts configuration
* doc: update default manuals
* flow: support episodic detection
* help: upper case proto acronyms etc
* http_inspect: apply request/response depth to packet data
* http_inspect: suppress raw packet inspection beyond request/response depth
* main: Export AnalyzerCommand and main_broadcast_command()
* rules: fix path variable expansion
* search_engine: rename inspect_stream_inserts to detect_raw_tcp for clarity
  default to true for 2.X rule sets
* rules: update fast pattern selection to exclude redundant port groups
  when service groups are present
* wizard: count user scans and hits separate from tcp

2018-01-29: build 242

* build: add STATIC to add_library call of port_scan to build it statically
  otherwise link will fail (Makefile.am already build only the static version);
  Thanks to Fabrice Fontaine <fontaine.fabrice@gmail.com>
* doc: update snort2lua for .rules files
* doc: fixed some typos
* expect: removed a single-element structure ExpectFlows
* file_api: give FilePolicyBase a default virtual destructor
* file: gracefully handle not having file policy configured in dce_smb
* flow: provided access to all expected flows created by a packet
* inspection events: added mandatory expected flow pub sub support
* inspector_manager: fix acquire and use of default policy
* profiler: fixed missing include
* sfdaq: export can_whitelist() and modify_flow_opaque()file_api:
  move VerdictName array out of file_api.h
* snort2lua: fix file_rule_path and fw_log_size handling in firewall preprocessor
* snort2lua: make sure file_magic table comes before file_id table
* snort2lua: detect commented 'alert' rules and convert them from snort to snort3 format
  Leave the rules commented out in the snort3 rules file
* snort2lua: convert *.rules files line-by-line
* unit tests: updated Catch
* unit tests: added ability to run Catch tests from dynamic modules
* utils, flatbuffers: added a uniform interface for 64-bit endian swaps

2017-12-15: build 241

* add back the ref count for file config
* alert_csv: various fixes to match alert_json
* alert_json: tcp_ack, tcp_seq, and tcp_win are (base 10) integers
* alert_json: various fixes;
  Thanks to Noah Dietrich <noah_dietrich@86penny.org> for reporting the issues
* appid: close all Lua states when thread exits
* appid: gracefully handle failed Lua state instantiation;
  Thanks to Noah Dietrich <noah_dietrich@86penny.org> for reporting the issue
* appid: only update session flags and discovery state if service id actually set to http
* appid: patch to update the appid discovery state when an http event results in setting of the
  service id for a flow
* appid: return false from is_third_party_appid_available when no third party module is available
* appid: tweak warnings and errors
* binder: activate profiler support
* binder: add FIXIT re creating default bindings when the wizard is not configured
* binder: fix ingress / egress test
* binder: minor perf and readability tweaks
* build: fixed build issues on OSX with clang with cd_pbb, alert_json
* build: fixed several dyanmic modules on OSX / clang
* build: suppress appid warnings for valid case statement fall throughs
* byte_test: fix string bounds check
* catch: Update to Catch v2.0.1
* cmake: add --define to configure_cmake.sh for arbitrary defines
* codec: added wlan support for arp_spoof
* codec: updated MIPv6 and merged cd_pim.cc, cd_swpie.cc and cd_sun_ud.cc to cd_bad_proto.cc
* conf: remove OPTIONS from SIP and HTTP spells to avoid confusion with RTSP
* conf: remove client to server spells for FTP, IMAP, POP, and SMTP to avoid false pickups
* control: must execute from default policy only
* control: process flow first
* cppcheck: More miscellaneous fixes, mostly for new Catch
* daq: explicitly initialize more fields in SFDAQInstance constructor
* daq: handle real IP and port
* data_bus: also publish to default policy
* data_bus: refactor basic access for pub / sub
* dce: use service names from rules (dce_smb = netbios-ssn; dce_tcp / dce_udp = dcerpc)
* detection: fix option tree looping issue
* detection: rename ServiceInfo to SignatureServiceInfo
* doc: fix type in style section
* doc: update default manuals
* file api: move file verdict enforcement out of file policy
* file api: support file verdict delay during signature lookup
* file policy and file config update to allow user define customized file policy through file api
* file policy: add support for file event logging
* file_api: Set the FileContext verdict, not a local verdict
* file_id: add interface to access file info from file capture
* file_id: support groups
* hash: Rename SFGHASH, SFXHASH, SFHASHFCN to something resonable
* http_inspect: add profiler support
* http_inspect: fix bugs related to stream interaction
* http_inspect: use configured max_pdu as base target reassembly size
* inspection: default policy mode depends on adaptor mode
* ips options: error if lookup fails due to bad case, typos, etc;
  Thanks to Noah Dietrich <noah_dietrich@86penny.org> for reporting the issue
* memory: no stats output unless configured
* normalizer: added test mode
* normalizer: fix enable checks
* parsing: resolve paths from the current config directory instead of process directory
* policy: added inspection policy config
* port_scan: add alert_all to make alerting on all events in window optional
* port_scan: fix flow checks
* profiler: fix focus of eventq
* reputation: tweak warning message
* rules: default msg = "no msg in rule"
* sfrt: remove cruft and reformat header
* shell: fixed crash when issuing control commands
* sip: use log splitter for tcp
* snort2lua: --bind-wizard will add a trailing binding to the default wizard in each binder
* snort2lua: Convert file_magic.conf to Lua format
* snort2lua: added inspection uuid
* snort2lua: added na_policy_mode. added ability amend tables if created
* snort2lua: added normalize_tcp: ftp
* snort2lua: fix stream_size: to_client, to_server conversion
* snort2lua: future proof --bind-wizard binding order
* snort2lua: no sticky buffer for relative pcre
* snort2lua: remove when udp from binding to support tcp too
* snort2lua: tweak const name for clarity (internal)
* snort2lua: urilen:<> --> bufferlen:<=>
* snort: do not dlclose plugins at shutdown during REG_TEST to avoid borked backtraces
  from LeakSanitizer
* soid: allow stub to contain any or all options
--rule-to-*: use whole soid arg as suffix to rule and len identifiers; make static
* stream: change tcp idle timeout to 3600 to match 2.X nominal timeout
* stream_*: separate session profiler data from flow cache profiler data
* stream_ip: fix non-frag counting
* stream_size: fix eval packet checks
* stream_tcp: delete superfluous memsets to zero
* stream_tcp: ignore flush requests on unitialized sessions (early abort condition)
* stream_tcp: instantiate wizard only when needed
* stream_tcp: remove empty default state action
* stream_user: clear splitter properly
* target_based: Install header
* wizard: abort if no match
* wizard: activate profiler support
* wizard: usage is inspect

2017-10-31: build 240

* active: fix packet modify vs resize handling
* alert_csv: rename dgm_len to pkt_len
* alert_csv: add b64_data, class, priority, service, vlan, and mpls options
* alert_json: initial json event logger
* alerts: add log_references to store and log rule references with alert_full
* appid: enable SSL certificate pattern matching
* appid: fix build with LuaJIT 2.1
* appid: reorganize AppIdHttpSession to minimize padding
* appid: add count for applications detected by port only
* appid: create exptected flow immediately after ftp PORT command for active mode
* appid: handle sip events before packets
* appid: overhaul peg counting for discovered appids
* appid: use ac_full search method since it supports find_all; force enable dfa flag
* binder: added network policy selection
* binder: added zones
* binder: allow src and dst specifications for ports and nets
* binder: check interface on packet instead of flow
* binder: fixed nets check falling through on failure
* build: clean up a few ICC 2018 and GCC 7 warnings
* build: fix linking against external libiconv with autotools
* build: fix numerous analyzer errors and leaks
* build: fix numerous clang-tidy warnings
* build: fix numerous cppcheck warnings
* build: fix numerous valgrind errors
* build: fixed issues on OSX
* catch: update to Catch v1.10.0
* cd_icmp6: fix encoded cksum calculation
* cd_pbb: initial version of codec for 802.1ah;
  Thanks to jan hugo prins <jhp@jhprins.org> for
  reporting the issue
* cd_pflog: fix comments;
  Thanks to Markus Lude <markus.lude@gmx.de> for the 2X patch
* content: fix relative loop condition
* control: delete the old binder while reloading inspector
* control: update binder with new inspector
* daq: add support for DAQ_VERDICT_RETRY
* daq: add support for packet trace
* daq: add support tunnel bypass for IP 4IN4, IP 6IN6, GRE and MPLS by config and flags
* data_log: update to new http_inspect
* dce_rpc: remove connection-oriented rules from dce_smb module
* dce_smb: unicode filename support
* doc: add module usage and peg count type
* doc: add POP, IMAP and SMTP to user manual features
* doc: add port scan feature
* flow key: support associating router solicit/reply packets to a single session
* http_inspect: HTTP headers no longer avoid detection when message unexpectedly ends after
  status line or headers
* http_inspect: add random increment to message body division points
* http_inspect: added http_raw_buffer rule option
* http_inspect: create message sections with body data that has been dechunked and unzipped but
  not otherwise nortmalized
* http_inspect: handle borked reassembly gracefully;
  Thanks to João Soares <joaopsys@gmail.com> for reporting the issue
* http_inspect: support for u2 extra data logging
* http_inspect: test tool improvements
* http_inspect: true IP enhancements
* inspectors: add control type and ensure appid is run ahead of other controls
* inspectors: add peg count for max concurrent sessions
* ips: add uuid
* loggers: add base64 encoder based on libb64 from devolve
* loggers: use standard year/mon/day format
* main: fix potential memory leak when queuing analyzer commands
* memory: align allocator metadata such that returned memory is also max_align_t-aligned
* memory: output basic startup heap stats
* messages: output startup warnings and errors to stderr instead of stdout
* messages: redirect stderr to syslog as well
* modules: add usage designating global, context, inspect, or detect policy applicability
* mss: add extra rule option to check mss
* parser: disallow invalid port range !:65535 (!any)
* parser: tweak performance
* pcre: fix relative search with ^
* pop: service name is pop3
* replace: fix activation sequence
* rules: warn only once per gid:sid of no fast pattern
* search_engine: port the optimized port table compilation from 2.9.12
* search_engines: Fix case sensitive ac_full DFA matching
* shell: delete inspector from the default inspection policy
* shell: fix --pause to accept control commands while in paused state
* sip: sip_method can use data from any sip inspector of any inspection policy
* snort.lua: align default conf closer to 2.X
* snort.lua: expand default conf for completeness and clarity
* snort_defaults.lua: update default servers and ports
* snort2lua: correctly identify ftpbounce and sameip as unsupported rule options
* snort2lua: added XFF configuration to unsupported list
* snort2lua: added config protected_content to deleted list
* snort2lua: added config_na_policy_mode to unsupported list
* snort2lua: added dynamicoutput to deleted list
* snort2lua: added firewall to unsupported list
* snort2lua: added nap.rules zone translation
* snort2lua: added nap_selector support
* snort2lua: added nap_selector to unsupported list
* snort2lua: added sf_unified2 to unsupported list and matching log/alert to deleted
* snort2lua: bindings now merge and propagate to top level of corresponsing policy
* snort2lua: config policy_id converts to when ips_policy_id
* snort2lua: convert dsize:a<>b to dsize:a<=>b for consistency with other rule options
* snort2lua: do not convert sameip; handle same as ftpbounce (no longer supported)
* snort2lua: enforced ordering to bindings in binder table
* snort2lua: fix null char in -? output
* snort2lua: fixed extra whitespace generation
* snort2lua: logto is not supported
* snort2lua: removed port dce proxy bindings to fix http_inspect conflicts
* snort2lua: search_engine.split_any_any now defaults to true
* snort: -T does not compile mpse; --mem-check does
* snort: add warnings count to -T ouptut
* snort: add --dump-msg-map
* snort: exit with zero from usage
* snort: fix --dump-builtin-rules to accept optional module prefix
* stdlog: support snort 3> log for text alerts
* target: add rule option to indicate target of attack
* thread: add logging directory ID offset controlled by --id-offset option
* u2spewfoo: fix build on FreeBSD
* unified2: add legacy_events bool for out-of-date barnyard2
* unified2: log buffers as cooked packets with legacy events
* wscale: add extra rule option to check tcp window scaling

2017-07-25: build 239

* rules: remove sample.rules; Talos will publish Snort 3 rules on snort.org
* logging: fix handling of out of range timeval;
  Thanks to kamil@frankowicz.me for reporting the issue
* wizard: fix direction issue
* wizard: fix imap spell

2017-07-24: build 238

* check: update hyperscan and regex tests
* cpputests: clean up some header include issues
* daq_socket: update to support query of pci
* detection: fix debug print of fast pattern only
* detection: rule evaluation trace utility
* doc: update concepts and differences
* file_api: memory leak fixed
* file_id: fixes for file capture exit
* http_inspect: added 119:97 for lower case letters in version field
* http_inspect: alert 119:96 added for unsolicited 206 response
* http_inspect: specific alert added 119:95 for Content-Encoding chunked
* ipv6: fix flow label access method;
  Thanks to schrx3b6 for the patch
* loggers: remove units options; all limits expressed in MB
* mpse: Remove Intel Soft CPM support
* mpse: make regex capability generic
* mpse: only use literals for fast patterns if search_method is not hyperscan
* output: add packet trace feature
* perf_monitor: fixed main table (perf_monitor) having same name as pegs for
* perfmon field
* regex: fix pass through of mpse flags to hyperscan
* replace: do not trip over fast pattern only
* rpc: revert to positional params, fix tcp logic, clean up formatting
* rules: promote metadata:service to a separate option since it is not metadata
* snort2lua: Fixed incorrect file names errors
* snort2lua: move footprint to stream from stream_tcp
* spell check: fix message and comment typos
* stream: add ip_proto as part of flow key
* stream: fix user dependency on flush bucket
* text logs: fix default unlimited file size
* u2: add event3 to u2spewfoo
* u2: convert thread local buffers to heap
* u2: deprecate ip4 and ip6 specific events and add a single event for both
* u2: remove obsolete configurations
* u2: support mixed IP versions

2017-07-13: build 237

* build: add support for appending EXTRABUILD to the BUILD string
* build: Clean up some ICC 2017 warnings
* build: clean up some GCC 7 warnings
* build: support OpenSSL 1.1.0 API
* build: clean up some cppcheck warnings
* appid: port some missing 2.9.X FEAT_OPEN_APPID code
* appid: fix thread-unsafe sharing of HTTP pattern tables
* DAQ: fix leaking instance memory when configure fails
* daq_hext and daq_file: pass PCI via query method
* icmp6: reject non-ip6, raise 116:474
* http_inspect: header normalization improvements
* http_inspect: port fixes for UTF decoding
* http_inspect: added 119:87 - 119:90 for expect / continue issues
* http_inspect: added 119:91 for Transfer-Encoding header not valid for HTTP 1.0
* http_inspect: added 119:92 for Content-Transfer-Encoding
* http_inspect: added 119:93 for issues with chunked message trailers
* PDF decompression: fix missing reset in state machine transition
* ftp_server: implement splitter to improve EOF processing
* port_scan: merge global settings into main module and other improvements
* perf_monitor: add JSON formatter
* ssl: add splitter to improve PDU processing
* detection: fix segfault in DetectionEngine::idle sans thread_init
* rules: tolerate spaces in positional parameters;
  Thanks to Joao Soares for reporting the issue
* ip and tcp options: fix max length handling and clean up logging
* cmg: improved alert formatting
* doc: updates re control channel
* snort2lua: added line number and file name to error output
* snort2lua: fix removal of ignore_ports in stream_tcp.small_segments
* snort2lua: fix heap-use-after-free for preprocessors and configs with no arguments
* snort2lua: update for port_scan

2017-06-15: build 236

* appid: clean up shutdown stats
* appid: fix memory leak
* conf: update defaults
* decode: updated ipv6 valid next headers
* detection: avoid superfluous leaf nodes in detection option trees
* http_inspect: improved handling of badly terminated chunks
* http_inspect: improved transfer-encoding header processing
* ips options: add validation for range check types such as dsize
* perf_monitor: add more tcp and udp peg counts
* perf_monitor: update cpu tracker output to thread_#.cpu_*
* port_scan: alert on all scan attempts so blocking is possible
* port_scan: make fully configurable
* sip: fix get body buffer for fast patterns
* ssl: use stop-and-wait splitter (protocol aware splitter is next)
* stream_ip: fix 123:7

2017-06-01: build 235

* http_inspect: improve handling of improper bare \r separator
* appid: fix bug where TNS detector corrupted the flow data object
* search_engine: set range for max_queue_events parameter;
  Thanks to Navdeep.Uniyal@neclab.eu for reporting the issue
* arp_spoof: reject non-ethernet packets
* stream_ip: remove dead code and tweak formatting
* ipproto: remove unreachable code
* control_mgmt: add support for daq module reload
* control_mgmt: add support for unix sockets
* doc: update default manuals
* doc: update differences section
* doc: update README

2017-05-21: build 234

* byte_math: port rule option from 2X and add feature documentation
* pgm: don't calculate checksum if header length is not divisible by 4
* appid: fix sip event handling, http pattern lists, thread locals
* build: fix issues with OpenSolaris and FreeBSD builds
* cmake: fix issues with libpcap and miscellaneous
* offload: refactor for initial (experimental) version of regex offload to other threads
* cmg: revamp hex buffer dump format with 16 or 20 bytes per line
* rules: reject positional parameters containing spaces

2017-05-11: build 233

* packet manager: ensure ether type proto ids don't masquerade as ip proto ids;
  Thanks to Bhargava Shastry <bshastry@sec.t-labs.tu-berlin.de> for reporting the issue
* codec manager: fix off-by-1 mapping array size;
  Thanks to Bhargava Shastry <bshastry@sec.t-labs.tu-berlin.de> for reporting the issue
* codec: fix extraction of ether type from cisco metadata
* appid: add new unit tests to the cmake build, fix missing lib reference to sfip
* sfghash: clean up and add unit tests
* http: fix 119:38 false positive
* main: fix compiler warnings when SHELL is not enabled
* perf_monitor: fix flatbuffers handling of empty strings
* modbus: port fix for false positives on length field
* http: port simple UTF decoding w/o byte order mark
* build: updated code to resolve cppcheck warnings
* cleanup: fix typos in source code string literals and comments
* doc: fix typos

2017-04-28: build 232

* build: clean up Intel compiler warnings and remarks
* build: fix FreeBSD compilation issues
* cmake: fix building with and without flatbuffers present
* autoconf: check for lua.hpp as well as luajit.h to ensure C++ support
* shell: make commands non-blocking
* shell: allow multiple remote connections
* snort2lua: fix generated stream_tcp bindings
* snort2lua: fix basic error handling with non-conformant 2.X conf
* decode: fix 116:402
* dnp3:  fix 145:5
* appid: numerous fixes and cleanup
* http_server: removed (use new http_inspect instead)
* byte_jump: add bitmask and from_end (from 2.9.9 Snort)
* byte_extract: add bitmask (from 2.9.9 Snort)
* flatbuffers: add version to banner if present
* loggers: build alert_sf_socket on all platforms

2017-04-07: build 231

* add decode of MPLS in IP
* add 116:171 and 116:173 cases (label 0 or 2 in non-bottom of stack)
* cleanup: remove dead code

2017-03-27: build 230

* require hyperscan >= 4.4.0, check runtime support;
  Thanks to justin.viiret@intel.com for submitting the patch
* fix search tool issue with empty pattern database;
  Thanks to justin.viiret@intel.com for reporting the issue
* fix sip_method to error out if sip not instantiated
* major appid overhaul to address lingering concerns: refactor, cleanup,
  simplify
* major detection overhaul to address lingering concerns: refactor, cleanup,
  release memory ASAP
* add FlatBuffers output format to perf_monitor
  also added tool to convert FlatBuffers files to yaml
* add regex.fast_pattern; do not use for fast pattern unless explicitly indicated
* update copyrights to 2017

2017-03-17: build 229

* fixed mpse to ensure all search methods return consistent results
* updated search tool to use fast pattern config's search method
  (benefits appid, http_inspect, imap, pop, and smtp)
* snort2lua parsing bug fixes to recognize incomplete constructs
* http_inspect: added alert 119:81 for nonprinting character in header name
* http_inspect: added alert 119:82 for bad Content-Length value
* http_inspect: added alert 119:83 for header wrapping; CR and LF parsed as whitespace

2017-03-02: build 228 - Alpha 4

* update hypercsan mpse: print error message and erroneous pattern when compilation fails
* update rule parser: add multiple byte orders warning
* fix pid file: create regardless of priv drop settings
* fix dce_rpc: mark generated iface patterns as literal
* snort2lua: mark appid conf and thirdparty_appid_dir as unsupported (temporary)
* snort2lua: fix a couple of typos in table API output
* snort2lua: fix sticky buffer following uricontent
* doc: add DAQ configuration documentation
* doc: move LibDAQ README to Reference, update, and fix typos
* doc: update default manuals

2017-02-24: build 227

* allow arbitrary / unused gids in text rules
* support DAQs w/o explicit sources (nfq, ipfw)
* fix up peg help (remove _)
* fix u2 logging of PDUs

2017-02-16: build 226

* add PDF/SWF decompression to http_inspect
* add connectors to generated reference parts of manual
* add feature documentation for HA, side_channel, and connectors
* add feature documentation for http_inspect
* update default manuals
* fix privilege dropping and chroot behavior
* fix perf_monitor segfault when tterm is called before tinit
* fix stream_tcp counter underflow bug and handle max and instant stats
* fix lzma length calculation bug
* fix bogus 129:20 alerts
* fix back orifice compiler warning with -O3
* fix bug that could cause hang on ctl-C
* fix memory leak after reload w/o changing search engine
* fix off by one error when reassembling after TCP FIN received
* fix cmake doc build to include plugins on SNORT_PLUGIN_PATH
* fix compiler warnings in dce_http_server and dce_http_proxy
* fix appid reload issue
* snort2lua - changes for rpc over http
* snort2lua - changes to convert config alertfile: <filename>
* snort2lua - changes to add file_id when smb file inspection is on
* snort2lua - add deprecated option stream5_tcp: log_asymmetric_traffic

2017-02-01: build 225

* implement RPC over HTTP by adding dce_http_server and dce_http_proxy
* port disable_replace option from snort 2.x and add snort2lua support
* port ssh tunnel over http detection
* fix stream splitter handling during final flush of session data
* fix appid to use HTTP inspection events to detect webdav methods
* fix unit test build to work w/o REG_TEST
* fix shell to add missing newline to Lua execution error responses
* fix support for content strings with escaped quotes ("foo\"bar");
  Thanks to secres@linuxmail.org for reporting the issue
* fix various reload issues
* fix various thread sanitizer issues
* fix session disposal to always be after logging
* fix appid pattern matching issues
* fix appid dns flow counts
* fix shell resume after command line --pause
* fix sd_pattern validation boundary conditions
* build: don't disable asserts when compiling with code coverage
* autoconf: update to latest versions of autoconf-archive macros
* main: add asynchronous, broadcastable analyzer commands
* add salt to flow hash
* normalize peg names to lower snake_case
* update default manuals

2017-01-17: build 224

* fix various stream_tcp flush issues
* fix various cmake issues
* fix appid counting of kerberos flows
* fix expected flow leak when expiring nodes during lookup;
  Thanks to João Soares <joaosoares11@hotmail.com> for reporting the issue
* fix autoconf retrieving PCRE cppflags from pkg-config
* fix stream_user reassembly
* remove unused appid.thirdparty_appid_dir
* build and install plugins as modules instead of libraries
* obfuscate stream rebuilt payload
* updates for latest zlib
* disable smb2 processing when file service is disabled
* refactor includes; prune the set of installed headers
* don't build alert_sf_socket on OSX
* added CPP flags used to build Snort to snort.pc for extras and other
  plugins to use

2016-21-16: build 223

* port 2983 smb active response updates
* fix reload crash with file inspector
* fix appid service dispatch handling issue;
  Thanks to João Soares <joaosoares11@hotmail.com> for reporting the issue
* fix paf-type flushing of single segments;
  Thanks to João Soares <joaosoares11@hotmail.com> for reporting the issue
* fix daemonization;
  Thanks to João Soares <joaosoares11@hotmail.com> for reporting the issue
* also fixes double counting of reassembled buffers
* fix fallback from paf to atom splitter if flushing past gap
* fix thread termination segfaults after DAQ module initialization fails
* fix non-x86 builds - do not build tsc clock scaling
* added appid to user manual features
* update default user manuals
* minor refactor of flush loop for clarity
* improve http_inspect Field class
* refactor plugin loading

2016-12-16: build 222

* add JavaScript Normalization to http_inspect
* fix appid service check dispatch list
* fix modbus_data handling to not skip options;
  Thanks to FabianMalte.Kopp@b-tu.de for reporting the issue
* fix sensitive data filtering documentation issues
* build: Illumos build fixes
* build: Address some cppcheck concerns
* miscellaneous const tweaks
* reformat builtin rule text for consistency
* reformat help text for consistency
* refactor user manual for clarity
* update default user manuals

2016-12-09: build 221

* fix appid handling of sip inspection events
* fix wizard to prevent use-after-free of service name
* fix various issues reported by cppcheck
* fix reload race condition
* fix cmake + clang builds
* add padding guards around hash key structs
* update manual for dce_* inspectors
* refactor IP address handling

2016-12-01: build 220

* fixed uu and qp decode issue
* fixed file signature calculation for ftp
* fixed file resume blocking
* fix 135:2 to be upon completion of 3-way handshake
* fix memory leak with libcrypto use
* fix multithreaded use of libcrypto
* fix default snort2lua output for gtp and modbus
* fix Lua ordering issue with net and port vars
* fix miscellaneous multithreading issues with appid
* fix comment in snort.lua re install directory use;
  Thanks to Yang Wang for sending the pull request
* add alternate fast patterns for dce_udp endianness
* removed underscores from all peg counts
* document sensitive data use
* user manual refactoring and updates

2016-11-21: build 219

* add dce auto detect to wizard
* add MIME file processing to new http_inspect
* add chapters on perf_monitor and file processing to user manual
* appid refactoring and cleanup
* many appid fixes for leaks, sanitizer, and analyzer issues
* fix appid pattern matching for http
* fix various race conditions reported by thread sanitizer
* fix out-of-order FIN handling
* fix cmake package name used in HS and HWLOC so that REQUIRED works
* fix out-of-tree doc builds
* fix image sizes to fit page;
  Thanks to wyatuestc for reporting the issue
* fix fast pattern selection when multiple designated;
  Thanks to j.mcdowell@titanicsystems.com for reporting the issue
* change -L to -K in README and manual;
  Thanks to jncornett for reporting the issue
* support compiling catch tests in standalone source files
* create pid file after dropping privileges
* improve detection and use of CppUTest in non-standard locations

2016-11-04: build 218

* fix shutdown stats
* fix misc appid issues
* rewrite appid loading of lua detectors
* add sip inspector events for appid
* update default manuals

2016-10-28: build 217

* update appid to 2983
* add inspector events from http_inspect to appid
* fix appid error messages
* fix flow reinitialization after expiration
* fix release of blocked flow
* fix 129:16 false positive

2016-10-21: build 216

* add build configuration for thread sanitizer
* port dce_udp fragments
* build: clean up some ICC warnings
* fix various unit test leaks
* fix -Wmaybe-uninitialized issues
* fix related to appid name with space and SSL position

2016-10-13: build 215

* added module trace facility
* port block malware over ftp for clients/servers that support REST command
* port dce_udp packet processing
* change search_engine.debug_print_fast_pattern to show_fast_patterns
* overhaul appid for multiple threads, memory leaks, and coding style
* fix various appid patterns and counts
* fix fast pattern selection
* fix file hash pruning issue
* fix rate_filter action config and apply_to clean up

2016-10-07: build 214

* updated DAQ - you *must* use DAQ 2.2.1
* add libDAQ version to snort -V output
* add support http file upload processing and process decode/detection depths
* port sip changes to avoid using NAT ip when calculating callid
* port dce_udp autodetect and session creation
* fix static analysis issues
* fix analyzer/pig race condition
* fix explicit obfuscation disable not working
* fix ftp_data: Gracefully handle cleared flow data
* fix LuaJIT rule option memory leak of plugin name
* fix various appid issues - initial port is nearing completion
* fix http_inspect event 119:66
* fix ac_full initialization performance
* fix stream_tcp left overlap on hpux, solaris
* fix/remove 129:5 ("bad segment") events
* file_mempool: fix initializing total pool size
* fix bpf includes
* fix builds for OpenSolaris
* expected: push expected flow information through the DAQ module
* expected: expected cache revamp and related bugfixes
* ftp_data: add expected data consumption to set service name and fix bugs
* build: remove lingering libDAQ #ifdefs
* defaults: update FTP default config based on Snort2's hardcoded one
* rename default_snort_manual.* to snort_manual.*
* build docs only by explicit target (make html|pdf|text)
* update default manuals to build 213
* tolerate more spaces in ip lists
* add rev to rule latency logs
* change default latency actions to none
* deleted non-functional extra decoder for i4l_rawip

2016-09-27: build 213

* ported full retransmit changes from snort 2X
* fixed carved smb2 filenames
* fixed multithread hyperscan mpse
* fixed sd_pattern iterative validation

2016-09-24: build 212

* add dce udp snort2lua
* add file detection when they are transferred in segments in SMB2
* fix another case of CPPUTest header order issues
* separate idle timeouts from session timeouts counts
* close tcp on rst in close wait, closing, fin wait 1, and fin wait 2
* doc: update style guide for 'using' statements and underscores
* packet_capture: Include top-level pcap.h for backward compatibility
* main: remove unused -w commandline option
* lua: fix conflict with _L macro from ctype.h on OpenBSD
* cmake: clean dead variables out of config.cmake.h
* build: fix 32-bit compiler warnings
* build: fix illumos/OpenSolaris build and remove SOLARIS/SUNOS defines
* build: remove superfluous LINUX and MACOS definitions
* build: remove superfluous OPENBSD and FREEBSD definitions
* build: entering 'std' namespace should be after all headers are included
* build: clean up u_int*_t usage
* build: remove SPARC support
* build: clean up some DAQ header inclusion creep

2016-09-22: build 211

* fix hyperscan detection with nocase
* fix shutdown sequence
* fix --dirty-pig
* fix FreeBSD build re appid / service_rpc

2016-09-20: build 210

* started dce_udp porting
* added HA details to stream/* dev_notes
* added stream.ip_frag_only to avoid tracking unwanted flows
* updated default stream cache sizes to match 2.X
* fixed tcp_connector_test for OSX build
* fixed binder make files to include binder.h
* fixed double counting of ip and udp timeouts and prunes
* fixed clearing of SYN - RST flows

2016-09-14: build 209

* add dce iface fast pattern for tcp
* add --enable-tsc-clock to build/use TSC register (on x86)
* update latency to use ticks during runtime
* tcp stream reassembly tweaks
* fix inverted detection_filter logic
* fix stream profile stats parents
* fix most bogus gap counts
* unit test fixes for high availability, hyperscan, and regex

2016-09-09: build 208

* fixed for TCP high availability
* fixed install of file_decomp.h for consistency between Snort and extras
* added smtp client counters and unit tests
* ported Smbv2/3 file support
* ported mpls encode fixes from 2983
* cleaned up compiler warnings

2016-09-02: build 207

* ported smb file processing
* ported the 2.9.8 ciscometadata decoder
* ported the 2.9.8 double and triple vlan tagging changes
* use sd_pattern as a fast-pattern
* rewrite and fix the rpc option
* cleanup fragbits option implementation
* finish up cutover to the new http_inspect by default
* added appid counts for rsync
* added http_inspect alerts for Transfer-Encoding and Content-Encoding abuse
* moved file capture to offload thread
* numerous fixes, cleanup, and refactoring for appid
* numerous fixes, cleanup, and refactoring for high availability
* fixed regex as fast pattern with hyperscan mpse
* fixed http_inspect and tcp valgrind errors
* fixed extra auto build from dist

2016-08-10: build 206

* ported appid rule option as "appids"
* moved http_inspect (old) to http_server (in extras)
* moved new_http_inspect to http_inspect
* added smtp.max_auth_command_line_len
* fixed asn1:print help
* fixed event queue buffer log size
* fixed make distcheck;
  Thanks to jack jackson <jsakcon@gmail.com> for reporting the issue

2016-08-05: build 205

* ported smb segmentation support
* converted sd_pattern to use hyperscan
* fixed help text for rule options ack, fragoffset, seq, tos, ttl,  and win
* fixed endianness issues with rule options seq and win
* fixed rule option session binary vs all

2016-07-29: build 204

* fixed issue with icmp_seq and icmp_id field matching
* fixed off-by-1 line number in rule parsing errors
* fix cmake make check issue with new_http_inspect
* added new_http_inspect unbounded POST alert

2016-07-22: build 203

* add oversize directory alert to new_http_inspect
* add appid counts for mdns, timbuktu, battlefield, bgp, and netbios services
* continue smb port - write and close command, deprecated dialect check, smb fingerprint
* fix outstanding strndup calls

2016-07-15: build 202

* fix dynamic build of new_http_inspect
* fix static analysis issues
* fix new_http_inspect handling of 100 response
* port appid detectors: kereberos, bittorrent, imap, pop
* port smb reassembly and raw commands processing
* snort2lua updates for new_http_inspect
* code refactoring and cleanup

2016-06-22: build 201

* initial appid port - in progress
* add configure --enable-hardened-build
* add configure --pie (position independent executable)
* add new_http_inspect alert for loss of sync
* add peg counts for new_http_inspect
* add peg counts for sd_pattern
* add file_log inspector to log file events
* add filename support to file daq
* add high availability support for udp and icmp
* add support for safe C library
* continue porting of dce_rpc - smb transaction processing (part 2)
* various snort2lua updates and fixes
* fix default prime tables for internal hash functions
* fix new_http_inspect bounds issues
* fix icc warnings
* miscellaneous cmake and auto tools build fixes
* openssl is now a mandatory dependency

2016-06-10: build 200

* continued porting of dce_rpc - smb transaction processing
* tweaked autotools build foo
* add / update unit tests
* fix additional memory leaks
* fix compiler warnings
* fix static analysis issues
* fix handling of bpf file failures

2016-06-03: build 199

* add new http_inspect alerts abusive content-length and transfer-encodings
* add \b matching to sensitive data
* add obfuscation for sensitive data
* add support for unprivileged operation
* fix link with dynamic DAQ
* convert legacy allocations to memory manager for better memory profiling

2016-05-27: build 198

* add double-decoding to new_http_inspect
* add obfuscation support for cmg and unified2
* cleanup compiler warnings and memory leaks
* fixup cmake builds
* update file processing configuration
* prevent profiler double counting on recursion
* additional unit tests for high availability
* fix multi-DAQ instance configuration

2016-05-02: build 197

* fix build of extras
* fix unit tests

2016-04-29: build 196

* overhaul cmake foo
* update extras to better serve as examples
* cleanup use of protocol numbers and identifiers
* continued stream_tcp refactoring
* continued dce2 port
* more static analysis memory leak fixes

2016-04-22: build 195

* added packet_capture module
* initial high availability for UDP
* changed memory_manager to use absolute instead of relative cap
* cmake and pkgconfig fixes
* updated catch headers to v1.4.0
* fix stream_tcp config leak
* added file capture stats
* static analysis updates
* DAQ interface refactoring
* perf_monitor refactoring
* unicode map file for new_http_inspect

2016-04-08: build 194

* added iterative pruning for out of memory condition
* added preemptive pruning to memory manager
* dce segmentation changes
* dce smb header checks port - non segmented packets
* added thread timing stats to perf_monitor
* fixed so rule input / output
* fixed protocol numbering issues
* fixed 129:18
* update extra version to alpha 4 -;
  Thanks to Henry Luciano <cuncator@mote.org> for reporting the issue
* remove legacy/unused obfuscation api
* fixed clang, gcc, and icc, build warnings
* fixed static analysis issues
* fixed memory leaks (more to go)
* clean up hyperscan pkg-config and cmake logic

2016-03-28: build 193

* fix session parsing abort handling
* fix shutdown memory leaks
* fix building against LuaJIT using only pkg-config
* fix FreeBSD build
* perf_monitor config and format fixes
* cmake - check all dependencies before fatal error
* new_http_inspect unicode initialization bug fix
* new_http_inspect %u encoding and utf 8 bare byte
* continued tcp stream refactoring
* legacy search engine cleanup
* dcd2 port continued - add dce packet fragmentation
* add configure --enable-address-sanitizer
* add configure --enable-code-coverage
* memory manager updates

2016-03-18: build 192

* use hwloc for CPU affinity
* fix process stats output
* add dce rule options iface, opnum, smb, stub_data, tcp
* add dce option for byte_extract/jump/test
* initial side channel and file connector for HA
* continued memory manager implementation
* add UTF-8 normalization for new_http_inspect
* fix rule compilation for sticky buffers
* host_cache and host_tracker config and stats updates
* miscellaneous warning and lint cleanup
* snort2Lua updates for preproc sensitive_data and sd_pattern option

2016-03-07: build 191

* fix perf_monitor stats output at shutdown
* initial port of sensitive data as a rule option
* fix doc/online_manual.sh for linux

2016-03-04: build 190

* fix console close and remote control disconnect issues
* added per-thread memcap calculation
* add statistics counters to host_tracker module
* new_http_inspect basic URI normalization with configuration options
* format string cleanup for parser logging
* fix conf reload by signal

2016-02-26: build 189

* snort2lua for dce2 port (in progress)
* replace ppm with latency
* added rule latency
* fixed more address sanitizer bugs
* fixed use of debug vs debug-msgs
* add missing ips option hash and == methods
* perf_monitor configuration
* fix linux + clang build errors
* trough rewrite

2016-02-22: build 188

* added delete/delete[] replacements for nothrow overload;
  Thanks to Ramya Potluri for reporting the issue
* fixed a detection option comparison bug which wasted time and space
* disable perf_monitor by default since the reporting interval should be set
* memory manager updates
* valgrind and unsanitary address fixes
* snort2lua updates for dce2
* build issue fix - make non-GNU strerror_r() the default case
* packet latency updates
* perfmon updates

2016-02-12: build 187

* file capture added - initial version writes from packet thread
* added support for http 0.9 to new_http_inspect
* added URI normalization of headers, cookies, and post bodies to new_http_inspect
* configure_cmake.sh updates to better support scripting
* updated catch header (used for some unit tests)
* continued dce2 port
* fixed misc clang and dynamic plugin build issues
* fixed static analysis issues and crash in new_http_inspect
* fixed tcp paws issue
* fixed normalization stats
* fixed issues reported by Bill Parker
* refactoring updates to tcp session
* refactoring updates to profiler

2016-02-02: build 186

* update copyright to 2016, add missing license blocks
* fix xcode builds
* fix static analysis issues
* update default manuals
* host_module and host_tracker updates
* start perf_monitor rewrite - 1st of many updates
* start dce2 port - 1st of many updates
* remove --enable-ppm - always enabled

2016-01-25: build 185

* initial host_tracker for new integrated netmap
* new_http_inspect refactoring for time and space considerations
* fix profiler depth bug
* fatal on failed IP rep segment allocation -;
  Thanks to Bill Parker
* tweaked style guide wrt class declarations

2016-01-08: build 184

* added new_http_inpsect rule options
* fixed build issue with Clang and thread_local
* continued tcp session refactoring
* fixed rule option string unescape issue

2015-12-11: build 183

* circumvent asymmetric flow handling issue

2015-12-11: build 182 - Alpha 3

* added memory profiling feature
* added regex fast pattern support
* ported reputation preprocessor from 2X
* synced to 297-262
* removed '_q' search method flavors - all are now queued
* removed PPM_TEST
* build and memory leak fixes

2015-12-04: build 181

* perf profiling enhancements
* fixed build issues and memory leaks
* continued pattern match refactoring
* fix spurious sip_method matching

2015-11-25: build 180

* ported dnp3 preprocessor and rule options from 2.X
* fixed various valgrind issues with stats from sip, imap, pop, and smtp
* fixed captured length of some icmp6 types
* added support for hyperscan search method using rule contents
  (regex to follow)
* fixed various log pcap issues
* squelch repeated ip6 ooo extensions and bad options per packet
* fixed arp inspection bug

2015-11-20: build 179

* user manaul updates
* fix perf_monitor.max_file_size default to work on 32-bit systems,;
  Thanks to noah_dietrich@86penny.org for reporting the issue
* fix bogus 116:431 events
* decode past excess ip6 extensions and bad options
* add iface to alert_csv.fields
* add hyperscan fast pattern search engine - functional but not yet used
* remove --enable-perf-profiling so it is always built
* perf profiling changes in preparation for memory profiling
* remove obsolete LibDAQ preprocessor conditionals
* fix arp inspection
* search engine refactoring

2015-11-13: build 178

* document runtime link issue with hyperscan on osx
* fix pathname generation for event trace file
* new_http_inspect tweaks
* remove --enable-ppm-test
* sync up auto tools and cmake build options

2015-11-05: build 177

* idle processing cleanup
* fixed teredo payload detection
* new_http_inspect cleanup
* update old http_inspect to allow spaces in uri
* added null check suggest by Bill Parker
* fix cmake for hyperscan
* ssl and dns stats updates
* fix ppm config
* miscellanous code cleanup

2015-10-30: build 176

* tcp reassembly refactoring
* profiler rewrite
* added gzip support to new_http_inspect
* added regex rule option based on hyperscan

2015-10-23: build 175

* ported gtp preprocessor and rule options from 2.X
* ported modbus preprocessor and rule options from 2.X
* fixed 116:297
* added unit test build for cmake (already in autotools builds)
* fixed dynamic builds (187 plugins, 138 dynamic)

2015-10-16: build 174

* legacy daemonization cleanup
* decouple -D, -M, -q
* delete -E
* initial rewrite of profiler
* don't create pid file unless requested
* remove pid lock file
* new_http_inspect header processing, normalization, and decompression tweaks
* convert README to markdown for pretty github rendering
  (contributed by gavares@gmail.com)
* perfmonitor fixes
* ssl stats updates

2015-10-09: build 173

* added pkt_num rule option to extras
* fix final -> finalize changes for extras
* moved alert_unixsock and log_null to extras
* removed duplicate pat_stats source from extras
* prevent tcp session restart on rebuilt packets;
  Thanks to rmkml for reporting the issue
* fixed profiler configuration
* fixed ppm event logging
* added filename to reload commands
* fixed -B switch
* reverted tcp syn only logic to match 2X
* ensure ip6 extension decoder state is reset for ip4 too since ip4
  packets may have ip6 next proto
* update default manuals

2015-10-01: build 172

* check for bool value before setting fastpath config option in PPM
* update manual related to liblzma
* fix file processing
* refactor non-ethernet plugins
* fix file_decomp error logic
* enable active response without flow
* update bug list

2015-09-25: build 171

* fix metadata:service to work like 2x
* fixed issues when building with LINUX_SMP
* fixed frag tracker accounting
* fix Xcode builds
* implement 116:281 decoder rule
* udpated snort2lua
* add cpputest for unit testing
* don't apply cooked verdicts to raw packets

2015-09-17: build 170

* removed unused control socket defines from cmake
* fixed build error with valgrind build option
* cleanup *FLAGS use in configure.ac
* change configure.ac compiler search order to prefer clang over gcc
* update where to get dnet
* update usage and bug list
* move extra daqs and extra hext logger to main source tree
* fix breakloop in file daq
* fix plain file processing
* fix detection of stream_user and stream_file data
* log innermost proto for type of broken packets

2015-09-10: build 169

* fix chunked manual install
* add event direction bug
* fix OpenBSD build
* convert check unit tests to catch
* code cleanup
* fix dev guide builds from top_srcdir

2015-09-04: build 168

* fixed build of chunked manual;
  Thanks to Bill Parker for reporting the issue
* const cleanup
* new_http_inspect cookie processing updates
* fixed cmake build issue with SMP stats enabled
* fixed compiler warnings
* added unit tests
* updated error messages in u2spewfoo
* changed error format for consistency with Snort
* fixed u2spewfoo build issue
* added strdup sanity checks;
  Thanks to Bill Parker for reporting the issue
* DNS bug fix for TCP
* added --catch-tags [footag],[bartag] for unit test selection

2015-08-31: build 167

* fix xcode warnings

2015-08-21: build 166

* fix link error with g++ 4.8.3
* support multiple script-path args and single files
* piglet bug fixes
* add usage examples with live interfaces;
  Thanks to Aman Mangal <mangalaman93@gmail.com> for reporting the problem
* fixed port_scan packet selection
* fixed rpc_decode sequence number handling and buffer setup
* perf_monitor fixes for file output

2015-08-14: build 165

* flow depth support for new_http_inspect
* TCP session refactoring and create libtcp
* fix ac_sparse_bands search method
* doc and build tweaks for piglets
* expanded piglet interfaces and other enhancements
* fix unit test return value
* add catch.hpp include from https://github.com/philsquared/Catch
* run catch unit tests after check unit tests
* fix documentation errors in users manual

2015-08-07: build 164

* add range and default to command line args
* fix unit test build on osx
* DAQ packet header conditional compilation for piglet
* add make targets for dev_guide.html and snort_online.html
* cleanup debug macros
* fix parameter range for those depending on loaded plugins;
  Thanks to Siti Farhana Binti Lokman <sitifarhana.lokman@postgrad.manchester.ac.uk>
  for reporting the issue

2015-07-30: build 163

* numerous piglet fixes and enhancements
* BitOp rewrite
* added more private IP address;
  Thanks to Bill Parker for reporting the issue
* fixed endianness in private IP address check
* fix build of dynamic plugins

2015-07-22: build 162

* enable build dependency tracking
* cleanup automake and cmake foo
* updated bug list
* added Lua stack manager and updated code that manipulated a persistent lua_State;
  Thanks to Sancho Panza (sancho@posteo.de) for reporting the issue
* piglet updates and fixes
* dev guide - convert snort includes into links
* fixup includes

2015-07-15: build 161

* added piglet plugin test harness
* added piglet_scripts with codec and inspector examples
* added doc/dev_guide.sh
* added dev_notes.txt in each src/ subdir
* scrubbed headers

2015-07-06: build 160 - Alpha 2

* fixed duplicate patterns in file_magic.lua
* warn about rules with no fast pattern
* warn if file rule has no file_data fp
* run fast patterns according to packet type
* update / expand shutdown output for detection
* binder sets service from inspector if not set
* allow abbreviated rule headers
* fix cmake build on linux w/o asciidoc
* add bugs list to manual
* fix memory leaks
* fix valgrind issues
* fix xcode analyzer issues

2015-07-02: build 159

* added file processing to new_http_inspect
* ported sip preprocessor
* refactoring port group init and start up output
* standardize / generalize fp buffers
* add log_hext.width
* tweak style guide
* fix hosts table parsing

2015-06-19: build 158

* nhttp splitter updates
* nhttp handle white space after chunk length
* refactor of fpcreate
* refactor sfportobject into ports/*
* delete flowbits_size, refactor bitop foo
* rename PortList to PortBitSet etc. to avoid confusion
* fix ssl assertion
* cleanup cache config

2015-06-11: build 157

* port ssl from snort
* fix stream_tcp so call splitter finish only if scan was called
* changed drop rules drop current packet only
* unchanged block rules block all packets on flow
* added reset rules to function as reject
* deleted sdrop and sblock rules; use suppressions instead
* refactored active module
* updated snort2lua

2015-06-04: build 156

* new_http_inspect switch to bitset for event tracking
* fixed stream tcp handling of paf abort
* fixed stream tcp cleanup on reset
* fixed sequence of flush and flow data cleanup for new http inspect

2015-05-31: build 155

* update default manuals
* fix autotools build of manual wrt plugins
* file processing fixup
* update usage from blog
* add file magic lua
* xcode analyzer cleanup

2015-05-28: build 154

* new_http_inspect parsing and event handling updates
* initial port of file capture from Snort
* stream_tcp reassembles payload only
* remove obsolete REG_TEST logging
* refactor encode_format*()
* rewrite alert_csv with default suitable for reg tests and debugging
* dump 20 hex bytes per line instead of 16
* add raw mode hext DAQ and logger; fix dns inspector typo for tcp checks
* document raw hext mode
* cleanup flush flags vs dir
* add alert_csv.separator, delete alert_test
* tweak log config; rename daq/log user to hext
* cleanup logging
* stream_tcp refactoring and cleanup

2015-05-22: build 153

* new_http_inspect parsing updates
* use buckets for user seglist
* fix u2 to output data only packets
* added DAQs for socket, user, and file in extras
* changed -K to -L (log type)
* added extra DAQ for user and file
* added stream_user for payload processing
* added stream_file for file processing

2015-05-15: build 152

* fixed config error for inspection of rebuilt packets
* ported smtp inspector from Snort
* static analysis fix for new_http_inspect

2015-05-08: build 151

* doc tweaks
* new_http_inspect message parsing updates
* misc bug fixes

2015-04-30: build 150

* fixed xcode static analysis issues
* updated default manuals
* added packet processing section to manual
* additional refactoring and cleanup
* fix http_inspect mpse search
* fixed urg rule option
* change daq.var to daq.vars to support multiple params
  reported by Sancho Panza
* ensure unknown sources are analyzed
* pop and imap inspectors ported

2015-04-28: build 149

* fixed build issue with extras

2015-04-28: build 148

* fixed default validation issue reported by Sancho Panza
* refactored snort and snort_config modules
* file id refactoring and cleanup
* added publish-subscribe handling of data events
* added data_log plugin example for pub-sub

2015-04-23: build 147

* change PT_DATA to IT_PASSIVE; supports named instances, reload, and consumers

2015-04-16: build 146

* added build of snort_manual.text if w3m is installed
* added default_snort_manual.text w/o w3m
* add Flow pointer to StreamSplitter::finish()

2015-04-10: build 145

* nhttp clear() and related changes
* abort PAF in current direction only
* added StreamSplitter::finish()
* allow relative flush point of zero
* added Inspector::clear()
* new http refactoring and cleanup
* new http changes - events from splitter
* fix dns assertion; remove unused variables

2015-03-31: build 144

* reworked autotools generation of api_options.h
* updated default manuals
* ported dns inspector

2015-03-26: build 143

* ported ssh inspector
* apply service from hosts when inspector already bound to flow
* ensure direction and service are applied to packet regardless of flow state
* enable active for react / reject only if used in configuration
* fixed use of bound ip and tcp policy if not set in hosts
* eliminate dedicated nhttp chunk buffer
* minor nhttp cleanup in StreamSplitter

2015-03-18: build 142

* fixed host lookup issue
* folded classification.lua and reference.lua into snort_defaults.lua
* apply defaults from parameter tables instead of relying on ctors etc
* fix static analysis issues reported by xcode
* change policy names with a-b form to a_b for consistency
* make all warnings optional
* fix ip and tcp policy defines
* fix ip and icmp flow client/server ip init
* added logging examples to usage

2015-03-11: build 141

* added build foo for lzma; refactored configure.ac
* enhancements for checking compatibility of external plugins
* added doc/usage.txt

2015-02-27: build 140

* uncrustify, see crusty.cfg
* updated documentation on new HTTP inspector, binder, and wizard

2015-02-26: build 139

* additional http_inspect cleanup
* documented gotcha regarding rule variable definitions in Lua
* sync 297 http xff, swf, and pdf updates

2015-02-20: build 138

* sync ftp with 297; replace stream event callbacks with FlowData virtuals

2015-02-12: build 137

* updated manual from blog posts and emails
* normalization refactoring, renaming
* fixed icmp4 encoding
* methods in codec_events and ip_util namespaces are now protected
  Codec methods
* 297 sync of active and codecs

2015-02-05: build 136

* fix up encoders
* sync stream with 297
* fix encoder check for ip6 extensions
* sync normalizations with 297

2015-01-29: build 135

* fixed freebsd build error
* fix default hi profile name
* updated default snort manuals

2015-01-26: build 134

* sync Mpse to 297, add SearchTool
* 297 sync for sfghash, sfxhash, tag, u2spewfoo, profiler and target based
* addition of mime decoding stats and updates to mime detection limits
* snort2lua changed to add bindings for default ports if not explicitly
  configured
* added md5, sha256, and sha512 rule options based on Snort 2.X
  protected_content

2015-01-20: build 133

* fixes for large file support on 32-bit Linux systems (reported by Y M)
* changed u2 base file name to unified2.log
* updated doc based on tips/tricks blog
* fixed active rule actions (react, reject, rewrite)
* moved http_inspect profile defaults to snort_defaults.lua
* add generalized infractions tracking to new_http_inspect
* updated snort2lua to override default tables (x = { t = v }; x.t.a = 1)
* additional codec refactoring
* added pflog codecs
* fixed stream_size rule option

2015-01-05: build 132

* added this change log
* initial partial sync with Snort 297 including bug fixes and variable
  renaming
* malloc info output with -v at shutdown (if supported)
* updated source copyrights for 2015 and reformatted license foo for
  consistency

2014-12-16: build 131

* fix asciidoc formatting and update default manuals
* updates to doc to better explain github builds
* fix default init for new_http_inspect
* fix cmake issues reported by Y M
* add missing g++ dependency to doc reported by Bill Parker
* add general fp re-search solution for fp buffers further restricted
  during rule eval; fixes issue reported by @rmkml
* add missing sanity checks reported by bill parker
* tweak READMEs

2014-12-11: build 130

* alpha 1 release

