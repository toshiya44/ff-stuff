/******************************************************************************
 * Originally from https://github.com/pyllyukko/user.js (MIT License)         *
 * It breaks too much stuff for me so I'm adding/removing stuff for my        *
 * convenience. I removed a some of the comments too, to make it readable.    *
 * Date: 2017-12-14                                                           *
 * Please notify me if there are any dupes and suggestions.                   *
 * A majority of the rules are directly imported from pyllyukko's user.js     *
 ******************************************************************************/

// Fix font rendering
// https://github.com/renkun-ken/MacType.Source/blob/master/README.md
//user_pref("gfx.font_loader.delay",  									-1);
user_pref("gfx.font_rendering.cleartype.always_use_for_content",		true);
user_pref("gfx.font_rendering.cleartype_params.cleartype_level",		100);
user_pref("gfx.font_rendering.cleartype_params.enhanced_contrast",  	100);
user_pref("gfx.font_rendering.cleartype_params.gamma",  				1400);
user_pref("gfx.font_rendering.cleartype_params.pixel_structure",		1);
user_pref("gfx.font_rendering.cleartype_params.rendering_mode", 		5);
user_pref("gfx.font_rendering.fallback.always_use_cmaps",				true);
user_pref("gfx.use_text_smoothing_setting", 							true);

// probably due to my system locale being jp, the fonts are in a disarry.
// i still have not figured out how this thingy works, but these prefs seem
// to override font settings.
user_pref("font.default.x-unicode", 			"sans-serif");
user_pref("font.default.x-western", 			"sans-serif");
user_pref("font.name.monospace.ja", 			"Consolas");
user_pref("font.name.monospace.x-unicode",		"Consolas");
user_pref("font.name.monospace.x-western",		"Consolas");
user_pref("font.name.sans-serif.ja",			"Arial");
user_pref("font.name.sans-serif.x-unicode",		"Arial");
user_pref("font.name.sans-serif.x-western",		"Arial");
user_pref("font.name.serif.ja",					"Arial");
user_pref("font.name.serif.x-unicode", 			"Arial");
user_pref("font.name.serif.x-western",			"Arial");
// user_pref("font.internaluseonly.changed",	false);

// https://wiki.mozilla.org/Platform/GFX/HardwareAcceleration
// https://www.macromedia.com/support/documentation/en/flashplayer/help/help01.html
// https://github.com/dillbyrne/random-agent-spoofer/issues/74
user_pref("gfx.direct2d.disabled",				true);
user_pref("layers.acceleration.disabled",		true);

// disables scan for plugins
user_pref("plugin.scan.plid.all",			false);
user_pref("app.update.auto",				false);

user_pref("geo.wifi.uri",				"");
user_pref("geo.wifi.logging.enabled",	false);

user_pref("browser.library.activity-stream.enabled",								false);
user_pref("browser.newtabpage.activity-stream.enabled",								false);
user_pref("browser.newtabpage.activity-stream.topSitesCount",						24);
user_pref("browser.newtabpage.activity-stream.feeds.topsites",						false);
user_pref("browser.newtabpage.activity-stream.feeds.snippets",						false);
user_pref("browser.newtabpage.activity-stream.feeds.section.highlights",			false);
user_pref("browser.newtabpage.activity-stream.feeds.section.topstories",			false);
user_pref("browser.newtabpage.activity-stream.feeds.section.topstories.options",	"");
user_pref("browser.newtabpage.activity-stream.telemetry",							false);
user_pref("browser.newtabpage.activity-stream.telemetry.ping.endpoint",				"");

// https://support.mozilla.org/en-US/questions/973320
// https://developer.mozilla.org/en-US/docs/Mozilla/Preferences/Preference_reference/browser.pagethumbnails.capturing_disabled
user_pref("browser.pagethumbnails.capturing_disabled",		true);
user_pref("browser.newtabpage.thumbnailPlaceholder",		true);

user_pref("browser.ping-centre.staging.endpoint",		"");
user_pref("browser.ping-centre.production.endpoint",	"");
user_pref("browser.ping-centre.log",					false);
user_pref("browser.ping-centre.telemetry",				false);
user_pref("browser.tabs.remote.warmup.enabled",			false);

user_pref("media.ffmpeg.enabled",						false);
user_pref("media.autoplay.enabled",						false);
user_pref("media.block-autoplay-until-in-foreground",	true);

// disable serviceworkers 
user_pref("dom.serviceWorkers.enabled",					false);
user_pref("dom.serviceWorkers.openWindow.enabled",		false);
user_pref("dom.workers.sharedWorkers.enabled",			false);
// user_pref("dom.workers.enabled",						false);

// Disable DRM content
// https://wiki.mozilla.org/Media/EME
user_pref("media.eme.enabled",					false);
user_pref("media.gmp-provider.enabled",			false);
user_pref("media.gmp-eme-adobe.enabled",		false);
user_pref("media.gmp-widevinecdm.enabled",		false);
user_pref("media.gmp-manager.url",				"");
user_pref("media.gmp-gmpopenh264.enabled",		false);
// user_pref("media.gmp-widevinecdm.version",	"");
// user_pref("media.gmp-eme-adobe.version",		"");

user_pref("breakpad.reportURL",								"");
user_pref("security.ssl.errorReporting.url",				"");
user_pref("toolkit.telemetry.cachedClientID",				"");
user_pref("toolkit.telemetry.server",						"");
user_pref("toolkit.telemetry.archive.enabled",				false);
user_pref("toolkit.telemetry.bhrPing.enabled",				false);
user_pref("toolkit.telemetry.firstShutdownPing.enabled",	false);
user_pref("toolkit.telemetry.shutdownPingSender.enabled",	false);
user_pref("toolkit.telemetry.newProfilePing.enabled",		false);
user_pref("toolkit.telemetry.updatePing.enabled",			false);
//user_pref("services.sync.telemetry.submissionInterval",	9999999999);

user_pref("browser.tabs.crashReporting.sendReport",				false);
user_pref("browser.crashReports.unsubmittedCheck.enabled",		false);
user_pref("browser.crashReports.unsubmittedCheck.autoSubmit",	false);

// https://archive.is/r62re
// https://hacks.mozilla.org/2016/03/a-webassembly-milestone/
// https://bugzilla.mozilla.org/show_bug.cgi?id=1278635
user_pref("javascript.options.wasm",				false);
user_pref("javascript.options.wasm_baselinejit", 	false);

// https://developer.mozilla.org/en-US/docs/Mozilla/Projects/Social_API
user_pref("social.whitelist",						"");
user_pref("social.directories",						"");
user_pref("social.shareDirectory",					"");
user_pref("social.activeProviders",					"");
user_pref("social.enabled", 						false);
user_pref("social.remote-install.enabled",			false);
user_pref("social.toast-notifications.enabled",		false);
user_pref("social.share.activationPanelEnabled",	false);

// usability
user_pref("browser.tabs.tabMinWidth",						100);
user_pref("browser.altClickSave",							true);
user_pref("browser.urlbar.trimURLs",						false);
user_pref("browser.urlbar.autocomplete.enabled",			true);
user_pref("browser.urlbar.doubleClickSelectsAll",			false);
user_pref("browser.urlbar.maxRichResults",					10);
user_pref("browser.urlbar.suggest.searches",				false);
user_pref("browser.urlbar.suggest.bookmark",				true);
user_pref("browser.urlbar.suggest.history",					true);
user_pref("browser.urlbar.suggest.openpage",				true);
user_pref("browser.urlbar.userMadeSearchSuggestionsChoice",	true);
user_pref("browser.urlbar.searchSuggestionsChoice",			false);

user_pref("browser.search.region",						"");
user_pref("browser.search.geoip.url",					"");
user_pref("browser.search.countryCode",					"");
user_pref("browser.search.update",						false);
user_pref("browser.search.suggest.enabled",				false);
user_pref("browser.search.context.loadInBackground",	true);
user_pref("browser.search.geoSpecificDefaults",			false);

user_pref("browser.display.background_color",	"#C0C0C0");

user_pref("middlemouse.paste",							true);
user_pref("middlemouse.scrollbarPosition",				true);
user_pref("layout.word_select.eat_space_to_next_word",	false);

user_pref("captivedetect.canonicalURL",				"");
user_pref("network.captive-portal-service.enabled",	false);

// stop autoupdating my stuff
// http://kb.mozillazine.org/App.update.silent
user_pref("app.update.auto",		false);
user_pref("app.update.enabled",		false);
user_pref("app.update.silent",		true);

user_pref("browser.tabs.loadBookmarksInTabs",			true);
user_pref("browser.tabs.loadBookmarksInBackground",		true);
user_pref("browser.tabs.closeWindowWithLastTab",		false);

// https://support.mozilla.org/en-US/kb/accessibility-services
user_pref("accessibility.force_disabled",			1);
user_pref("accessibility.typeaheadfind",			true);

user_pref("view_source.tab",				false);
user_pref("view_source.wrap_long_lines",	true);
user_pref("view_source.syntax_highlight",	true);

user_pref("extensions.greasemonkey.stats.prompted",			true);
user_pref("extensions.greasemonkey.stats.optedin",			false);

//user_pref("security.sandbox.content.level",		3);
//user_pref("dom.ipc.plugins.sandbox-level.flash",	2);

user_pref("network.dnsCacheEntries",			1000);
user_pref("network.dnsCacheExpiration",			40000);

// https://www.ghacks.net/2017/11/28/firefox-58-to-block-top-level-data-url-navigation/
user_pref("security.data_uri.block_toplevel_data_uri_navigations",	true);

user_pref("browser.startup.homepage_override.mstone",			"ignore");

//network.http.referer.spoofSource
//network.http.referer.hideOnionSource
//browser.tabs.restorebutton
//mousewheel.system_scroll_override_on_root_content.enabled;true
//extensions.getAddons.get.url;https://services.addons.mozilla.org/%LOCALE%/firefox/api/%API_VERSION%/search/?src=firefox&appVersion=%VERSION%

/******************************************************************************
 * HTML5 / APIs / DOM                                                         *
 *                                                                            *
 ******************************************************************************/

// disable Location-Aware Browsing
// http://www.mozilla.org/en-US/firefox/geolocation/
user_pref("geo.enabled",					false);

// Disable dom.mozTCPSocket.enabled (raw TCP socket support)
// https://trac.torproject.org/projects/tor/ticket/18863
// https://www.mozilla.org/en-US/security/advisories/mfsa2015-97/
// https://developer.mozilla.org/docs/Mozilla/B2G_OS/API/TCPSocket
user_pref("dom.mozTCPSocket.enabled",		false);

// Whether JS can get information about the network/browser connection
// Network Information API provides information about the system's connection type (WiFi, cellular, etc.)
// https://developer.mozilla.org/en-US/docs/Web/API/Network_Information_API
// https://wicg.github.io/netinfo/#privacy-considerations
// https://bugzilla.mozilla.org/show_bug.cgi?id=960426
user_pref("dom.netinfo.enabled",			false);

// Disable Web Audio API
// https://bugzil.la/1288359
user_pref("dom.webaudio.enabled",			false);

// Don't reveal your internal IP
// Disable WebRTC entirely
// Check the settings with: http://net.ipcalf.com/
// https://wiki.mozilla.org/Media/WebRTC/Privacy
user_pref("media.peerconnection.enabled",						false);
user_pref("media.peerconnection.ice.default_address_only",		true); // Firefox < 51
user_pref("media.peerconnection.ice.no_host",					true); // Firefox >= 51

// https://redd.it/2uaent
user_pref("media.peerconnection.video.enabled",				false);
user_pref("media.peerconnection.turn.disable",				true);
user_pref("media.peerconnection.use_document_iceservers",	false);
user_pref("media.peerconnection.identity.enabled",			false);
user_pref("media.peerconnection.identity.timeout",			1);.

// getUserMedia
// https://wiki.mozilla.org/Media/getUserMedia
// https://developer.mozilla.org/en-US/docs/Web/API/Navigator
// https://developer.mozilla.org/en-US/docs/Web/API/BatteryManager
// https://developer.mozilla.org/en-US/docs/Web/API/navigator.sendBeacon
// https://developer.mozilla.org/en-US/docs/Mozilla/Preferences/Preference_reference/dom.event.clipboardevents.enabled
// https://wiki.mozilla.org/Security/Reviews/Firefox/NavigationTimingAPI
// https://wiki.mozilla.org/WebAPI/Security/WebTelephony
user_pref("media.navigator.enabled",				false);
user_pref("beacon.enabled",							false);
user_pref("dom.battery.enabled",					false);
user_pref("dom.telephony.enabled",					false);
user_pref("dom.event.clipboardevents.enabled",		false);
user_pref("dom.enable_performance",					false);
user_pref("dom.enable_user_timing",					false);
user_pref("dom.select_events.enable",				false);
user_pref("dom.select_events.textcontrols.enabled",	false);
user_pref("clipboard.autocopy",						false);

// Dont let sites prevent context menus
// user_pref("dom.event.contextmenu.enabled",false);

// Speech recognition
// https://dvcs.w3.org/hg/speech-api/raw-file/tip/speechapi.html
// https://wiki.mozilla.org/HTML5_Speech_API
// https://developer.mozilla.org/en-US/docs/Web/API/SpeechSynthesis
user_pref("media.webspeech.recognition.enable",		false);
user_pref("media.webspeech.synth.enable",			false);

// Disable getUserMedia screen sharing
// https://mozilla.github.io/webrtc-landing/gum_test.html
user_pref("media.getusermedia.audiocapture.enabled",			false);
user_pref("media.getusermedia.screensharing.enabled",			false);
user_pref("media.getusermedia.screensharing.allowed_domains",	"");

// Disable sensor API
// https://wiki.mozilla.org/Sensor_API
user_pref("device.sensors.enabled",				false);

// http://kb.mozillazine.org/Browser.send_pings
// http://kb.mozillazine.org/Browser.send_pings.require_same_host
user_pref("browser.send_pings",						false);
user_pref("browser.send_pings.require_same_host",	true);

// Disable gamepad input
// http://www.w3.org/TR/gamepad/
user_pref("dom.gamepad.enabled",			false);

// Disable virtual reality devices
// https://developer.mozilla.org/en-US/Firefox/Releases/36#Interfaces.2FAPIs.2FDOM
user_pref("dom.vr.enabled",					false);
user_pref("dom.vr.oculus.enabled",			false);
user_pref("dom.vr.openvr.enabled",			false);
user_pref("dom.vr.osvr.enabled",			false);
user_pref("dom.vr.puppet.enabled",			false);
user_pref("dom.vr.test.enabled",			false);
user_pref("dom.vr.poseprediction.enabled",	false);

// PREF: Disable vibrator API
user_pref("dom.vibrator.enabled",			false);

// disable notifications
user_pref("dom.push.enabled",								false);
user_pref("dom.push.connection.enabled",					false);
user_pref("dom.push.serverURL", 							"");
user_pref("dom.push.userAgentID", 							"");
user_pref("dom.webnotifications.enabled",					false);
user_pref("dom.webnotifications.serviceworker.enabled",		false);

// disable webGL
// http://www.contextis.com/resources/blog/webgl-new-dimension-browser-exploitation/
// https://bugzilla.mozilla.org/show_bug.cgi?id=1171228
// https://developer.mozilla.org/en-US/docs/Web/API/WEBGL_debug_renderer_info
user_pref("webgl.disabled",							true);
// PREF: When webGL is enabled, use the minimum capability mode
user_pref("webgl.min_capability_mode",				true);
// PREF: When webGL is enabled, disable webGL extensions
// https://developer.mozilla.org/en-US/docs/Web/API/WebGL_API#WebGL_debugging_and_testing
user_pref("webgl.disable-extensions",				true);
// PREF: When webGL is enabled, force enabling it even when layer acceleration is not supported
// https://trac.torproject.org/projects/tor/ticket/18603
user_pref("webgl.disable-fail-if-major-performance-caveat",	true);
// PREF: When webGL is enabled, do not expose information about the graphics driver
user_pref("webgl.enable-debug-renderer-info",		false);

/******************************************************************************
 * Misc                                                                       *
 *                                                                            *
 ******************************************************************************/

// Disable face detection by default
user_pref("camera.control.face_detection.enabled",		false);

// Don't try to guess where i'm trying to go!!! e.g.: "http://foo" -> "http://(prefix)foo(suffix)"
// http://www-archive.mozilla.org/docs/end-user/domain-guessing.html
user_pref("browser.fixup.alternate.enabled",			false);

// https://trac.torproject.org/projects/tor/wiki/doc/TorifyHOWTO/WebBrowsers
user_pref("network.proxy.socks_remote_dns",			true);

// https://trac.torproject.org/projects/tor/ticket/18945
user_pref("network.manage-offline-status",				false);

// https://secure.wikimedia.org/wikibooks/en/wiki/Grsecurity/Application-specific_Settings#Firefox_.28or_Iceweasel_in_Debian.29
user_pref("javascript.options.methodjit.chrome",		false);
user_pref("javascript.options.methodjit.content",		false);

// CIS Mozilla Firefox 24 ESR v1.0.0 - 3.7 Disable JAR from opening Unsafe File Types
// http://kb.mozillazine.org/Network.jar.open-unsafe-types
user_pref("network.jar.open-unsafe-types",			false);

// CIS 2.7.4 Disable Scripting of Plugins by JavaScript
user_pref("security.xpconnect.plugin.unrestricted",		false);

// CIS Mozilla Firefox 24 ESR v1.0.0 - 3.8 Set File URI Origin Policy
// http://kb.mozillazine.org/Security.fileuri.strict_origin_policy
user_pref("security.fileuri.strict_origin_policy",				true);

// CIS 2.3.6 Disable Displaying Javascript in History URLs
// http://kb.mozillazine.org/Browser.urlbar.filter.javascript
user_pref("browser.urlbar.filter.javascript",			true);

// http://asmjs.org/
// https://www.mozilla.org/en-US/security/advisories/mfsa2015-29/
// https://www.mozilla.org/en-US/security/advisories/mfsa2015-50/
// https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-2712
user_pref("javascript.options.asmjs",				false);

// PREF: Disable video stats to reduce fingerprinting threat
// https://bugzilla.mozilla.org/show_bug.cgi?id=654550
// https://github.com/pyllyukko/user.js/issues/9#issuecomment-100468785
// https://github.com/pyllyukko/user.js/issues/9#issuecomment-148922065
user_pref("media.video_stats.enabled",				false);

// Don't reveal build ID
// Value taken from Tor Browser
// https://bugzil.la/583181
user_pref("general.buildID.override",						"20100101");
user_pref("browser.startup.homepage_override.buildID",		"20100101");

// PREF: Set Accept-Language HTTP header to en-US regardless of Firefox localization
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept-Language
user_pref("intl.accept_languages",				"en");

// PREF: Don't use OS values to determine locale, force using Firefox locale setting
// http://kb.mozillazine.org/Intl.locale.matchOS
user_pref("intl.locale.matchOS",				false);

/******************************************************************************
 * extensions / plugins                                                       *
 *                                                                            *
 ******************************************************************************/

// Require signatures
user_pref("xpinstall.whitelist.required",				true);
user_pref("extensions.update.enabled",					true);
user_pref("extensions.update.autoUpdateDefault",		false);
// user_pref("xpinstall.signatures.required",			true);
// user_pref("extensions.legacy.enabled",				true);

// Opt-out of add-on metadata updates
// https://blog.mozilla.org/addons/how-to-opt-out-of-add-on-metadata-updates/
user_pref("extensions.getAddons.cache.enabled",			false);

// Never activate flash and java
user_pref("plugin.state.flash",				0);
user_pref("plugin.state.java",				0);

// PREF: Disable sending Flash Player crash reports
user_pref("dom.ipc.plugins.flash.subprocess.crashreporter.enabled",	false);
user_pref("dom.ipc.plugins.flash.disable-protected-mode",			false);

// PREF: When Flash crash reports are enabled, don't send the visited URL in the crash report
user_pref("dom.ipc.plugins.reportCrashURL",							false);

// disable Gnome Shell Integration
user_pref("plugin.state.libgnome-shell-browser-plugin",		0);

// https://wiki.mozilla.org/Firefox/Click_To_Play
// https://blog.mozilla.org/security/2012/10/11/click-to-play-plugins-blocklist-style/
user_pref("plugins.click_to_play",					true);

// http://kb.mozillazine.org/Extensions.blocklist.enabled
user_pref("extensions.blocklist.enabled",			true);
user_pref("services.blocklist.update_enabled",		true);

// PREF: Decrease system information leakage to Mozilla blocklist update servers
// https://trac.torproject.org/projects/tor/ticket/16931
user_pref("extensions.blocklist.url",				"https://blocklist.addons.mozilla.org/blocklist/3/%APP_ID%/%APP_VERSION%/");

// PREF: Ensure you have a security delay when installing add-ons (milliseconds)
// http://kb.mozillazine.org/Disable_extension_install_delay_-_Firefox
// http://www.squarefree.com/2004/07/01/race-conditions-in-security-dialogs/
user_pref("security.dialog_enable_delay",			1000);

/******************************************************************************
 * firefox features / components                                              *
 *                                                                            *
 ******************************************************************************/

// WebIDE
// https://trac.torproject.org/projects/tor/ticket/16222
user_pref("devtools.webide.enabled",						false);
user_pref("devtools.webide.autoinstallADBHelper",			false);
user_pref("devtools.webide.autoinstallFxdtAdapters",		false);

// disable remote debugging
// https://developer.mozilla.org/docs/Tools/Remote_Debugging/Debugging_Firefox_Desktop#Enable_remote_debugging
// https://developer.mozilla.org/en-US/docs/Tools/Tools_Toolbox#Advanced_settings
// https://developer.mozilla.org/en-US/docs/Tools/Remote_Debugging/Debugging_Firefox_Desktop#Firefox_37_onwards
user_pref("devtools.debugger.remote-enabled",		false);
user_pref("devtools.chrome.enabled",				false);
user_pref("devtools.debugger.force-local",			true);

// https://wiki.mozilla.org/Platform/Features/Telemetry
// https://www.mozilla.org/en-US/legal/privacy/firefox.html#telemetry
// https://wiki.mozilla.org/Security/Reviews/Firefox6/ReviewNotes/telemetry
// https://gecko.readthedocs.org/en/latest/toolkit/components/telemetry/telemetry/preferences.html
// https://wiki.mozilla.org/Telemetry/Experiments
user_pref("toolkit.telemetry.enabled",				false);
user_pref("toolkit.telemetry.unified",				false);
user_pref("experiments.supported",					false);
user_pref("experiments.enabled",					false);
user_pref("experiments.manifest.uri",				"");
user_pref("experiments.supported",					false);
user_pref("experiments.activeExperiment",			false);
user_pref("network.allow-experiments",				false);

// Disable the UITour backend so there is no chance that a remote page
// can use it to confuse Tor Browser users.
user_pref("browser.uitour.enabled",				false);
// more uitours
user_pref("browser.onboarding.enabled", 								false);
user_pref("browser.onboarding.newtour",									"");
user_pref("browser.onboarding.updatetour",								"");
user_pref("browser.onboarding.notification.tour-ids-queue",				"");
user_pref("browser.onboarding.notification.max-prompt-count-per-tour",	0);
user_pref("browser.onboarding.shieldstudy.enabled",						false);

// PREF: Enable Firefox Tracking Protection
// https://wiki.mozilla.org/Security/Tracking_protection
// https://support.mozilla.org/en-US/kb/tracking-protection-firefox
// https://support.mozilla.org/en-US/kb/tracking-protection-pbm
// user_pref("privacy.trackingprotection.enabled",			true);
// user_pref("privacy.trackingprotection.pbmode.enabled",		true);

// PREF: Enable hardening against various fingerprinting vectors (Tor Uplift project)
// https://wiki.mozilla.org/Security/Tor_Uplift/Tracking
// https://bugzilla.mozilla.org/show_bug.cgi?id=1333933
user_pref("privacy.resistFingerprinting",						true);
user_pref("privacy.resistFingerprinting.block_mozAddonManager",	true);

// PREF: Spoof single-core CPU
// it comes with privacy.resistFingerprinting
// https://trac.torproject.org/projects/tor/ticket/21675
// https://bugzilla.mozilla.org/show_bug.cgi?id=1360039
// user_pref("dom.maxHardwareConcurrency",				2);

// Disable the built-in PDF viewer (CVE-2015-2743)
// https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-2743
user_pref("pdfjs.disabled",			true);
user_pref("pdfjs.enableWebGL",		false);

// Disable sending of the health report
// https://support.mozilla.org/en-US/kb/firefox-health-report-understand-your-browser-perf
// https://gecko.readthedocs.org/en/latest/toolkit/components/telemetry/telemetry/preferences.html
user_pref("datareporting.healthreport.uploadEnabled",	false);
user_pref("datareporting.healthreport.service.enabled",	false);
user_pref("datareporting.policy.dataSubmissionEnabled",	false);

// disable heartbeat
// https://wiki.mozilla.org/Advocacy/heartbeat
user_pref("browser.selfsupport.url",		"");
user_pref("browser.selfsupport.enabled",	false);

// Disable firefox hello
// https://wiki.mozilla.org/Loop
user_pref("loop.enabled",		false);
user_pref("loop.logDomains",	false);

// CIS 2.3.4 Block Reported Web Forgeries
// http://kb.mozillazine.org/Browser.safebrowsing.enabled
// http://kb.mozillazine.org/Browser.safebrowsing.malware.enabled
// http://kb.mozillazine.org/Safe_browsing
// https://support.mozilla.org/en-US/kb/how-does-phishing-and-malware-protection-work
// http://forums.mozillazine.org/viewtopic.php?f=39&t=2711237&p=12896849#p12896849
user_pref("browser.safebrowsing.enabled",				false);
user_pref("browser.safebrowsing.malware.enabled",		false);
user_pref("browser.safebrowsing.phishing.enabled",		false);
user_pref("browser.safebrowsing.blockedURIs.enabled",	false);

// Disable safe browsing remote lookups for downloaded files.
// This leaks information to google.
// https://www.mozilla.org/en-US/firefox/39.0/releasenotes/
// https://wiki.mozilla.org/Security/Application_Reputation
user_pref("browser.safebrowsing.downloads.enabled",						false);
user_pref("browser.safebrowsing.downloads.remote.enabled", 				false);
user_pref("browser.safebrowsing.downloads.remote.block_dangerous",		false);
user_pref("browser.safebrowsing.downloads.remote.block_dangerous_host",	false);
user_pref("browser.safebrowsing.downloads.remote.block_uncommon",		false);
user_pref("browser.safebrowsing.downloads.remote.url",					"");

// https://support.mozilla.org/en-US/kb/save-web-pages-later-pocket-firefox
user_pref("browser.pocket.enabled",		false);
user_pref("extensions.pocket.enabled",	false);
user_pref("extensions.pocket.api",		"");
user_pref("extensions.pocket.site",		"");

// disable screenshots addon
user_pref("extensions.screenshots.disabled",		true);
user_pref("extensions.screenshots.system-disabled",	true);

// disable Shield telemetry
// https://wiki.mozilla.org/Firefox/Shield
user_pref("extensions.shield-recipe-client.enabled",	false);
user_pref("extensions.shield-recipe-client.api_url",	"");
user_pref("extensions.shield-recipe-client.user_id",	"");
user_pref("app.shield.optoutstudies.enabled",			false);
user_pref("extensions.ui.experiment.hidden",			false);

user_pref("dom.flyweb.enabled",								false);
user_pref("extensions.webcompat-reporter.enabled",			false);
user_pref("extensions.webcompat-reporter.newIssueEndpoint",	"");
user_pref("media.decoder-doctor.new-issue-endpoint",		"");

user_pref("extensions.formautofill.experimental",			false);
user_pref("extensions.formautofill.heuristics.enabled",		false);
user_pref("extensions.formautofill.creditCards.enabled",	false);
user_pref("dom.forms.autocomplete.experimental",			false);

user_pref("devtools.onboarding.experiment",			"off");
//user_pref("devtools.onboarding.experiment.flipped
user_pref("devtools.onboarding.telemetry.logged",	false);

/******************************************************************************
 * automatic connections                                                      *
 *                                                                            *
 ******************************************************************************/

// Disable link prefetching
// http://kb.mozillazine.org/Network.prefetch-next
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Link_prefetching_FAQ
user_pref("network.prefetch-next",					false);

// http://kb.mozillazine.org/Network.dns.disablePrefetch
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Controlling_DNS_prefetching
user_pref("network.dns.disablePrefetch",			true);
user_pref("network.dns.disablePrefetchFromHTTPS",	true);

// https://bugzilla.mozilla.org/show_bug.cgi?id=1228457
user_pref("network.dns.blockDotOnion",				true);

// https://wiki.mozilla.org/Privacy/Reviews/Necko
user_pref("network.predictor.enabled",				false);

// https://wiki.mozilla.org/Privacy/Reviews/Necko#Principle:_Real_Choice
user_pref("network.seer.enabled",				false);

// Disable SSDP
// https://bugzil.la/1111967
user_pref("browser.casting.enabled",				false);

// https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections
user_pref("network.http.speculative-parallel-limit",	0);
user_pref("browser.aboutHomeSnippets.updateUrl",		"");

/******************************************************************************
 * HTTP                                                                       *
 *                                                                            *
 ******************************************************************************/

// Disallow NTLMv1
// https://bugzilla.mozilla.org/show_bug.cgi?id=828183
user_pref("network.negotiate-auth.allow-insecure-ntlm-v1",	false);

// https://bugzilla.mozilla.org/show_bug.cgi?id=855326
// https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Introducing_Content_Security_Policy
user_pref("security.csp.enable",				true);
user_pref("security.csp.experimentalEnabled",	true);

// Subresource integrity
// https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
// https://wiki.mozilla.org/Security/Subresource_Integrity
user_pref("security.sri.enable",				true);

/******************************************************************************
 * UI related                                                                 *
 *                                                                            *
 ******************************************************************************/
// PREF: Enable insecure password warnings (login forms in non-HTTPS pages)
// https://blog.mozilla.org/tanvi/2016/01/28/no-more-passwords-over-http-please/
// https://bugzilla.mozilla.org/show_bug.cgi?id=1319119
// https://bugzilla.mozilla.org/show_bug.cgi?id=1217156
user_pref("security.insecure_password.ui.enabled",		true);

// PREF: Disable new tab tile ads & preload
// http://www.thewindowsclub.com/disable-remove-ad-tiles-from-firefox
// http://forums.mozillazine.org/viewtopic.php?p=13876331#p13876331
// https://wiki.mozilla.org/Tiles/Technical_Documentation#Ping
user_pref("browser.newtab.preload",						false);
user_pref("browser.newtabpage.enhanced",				false);
user_pref("browser.newtabpage.compact",					true);
user_pref("browser.newtabpage.columns",					8);
user_pref("browser.newtabpage.rows",					8);
user_pref("browser.newtabpage.directory.ping",			"");
user_pref("browser.newtabpage.directory.source",		"data:text/plain,{}");
//user_pref("browser.newtabpage.directory.source",		"");

// CIS Version 1.2.0 October 21st, 2011 2.1.2 Enable Auto Notification of Outdated Plugins
// https://wiki.mozilla.org/Firefox3.6/Plugin_Update_Awareness_Security_Review
user_pref("plugins.update.notifyUser",				true);

// CIS Version 1.2.0 October 21st, 2011 2.1.3 Enable Information Bar for Outdated Plugins
user_pref("plugins.hide_infobar_for_outdated_plugin",		false);

// CIS Mozilla Firefox 24 ESR v1.0.0 - 3.6 Enable IDN Show Punycode
// http://kb.mozillazine.org/Network.IDN_show_punycode
user_pref("network.IDN_show_punycode",				true);

// PREF: Disable CSS :visited selectors
// https://blog.mozilla.org/security/2010/03/31/plugging-the-css-history-leak/
// https://dbaron.org/mozilla/visited-privacy
user_pref("layout.css.visited_links_enabled",			false);

// http://kb.mozillazine.org/Signon.autofillForms
// https://www.torproject.org/projects/torbrowser/design/#identifier-linkability
user_pref("signon.autofillForms",				false);

// PREF: Do not check if Firefox is the default browser
user_pref("browser.shell.checkDefaultBrowser",			false);

// PREF: Display a notification bar when websites offer data for offline use
// http://kb.mozillazine.org/Browser.offline-apps.notify
user_pref("browser.offline-apps.notify",			true);

/******************************************************************************
 * SECTION: Cryptography                                                      *
 ******************************************************************************/

// PREF: Enable HSTS preload list (pre-set HSTS sites list provided by Mozilla)
// https://blog.mozilla.org/security/2012/11/01/preloading-hsts/
// https://wiki.mozilla.org/Privacy/Features/HSTS_Preload_List
// https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security
user_pref("network.stricttransportsecurity.preloadlist",	true);

// PREF: Enable Online Certificate Status Protocol
// https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol
// NOTICE: OCSP leaks your IP and domains you visit to the CA when OCSP Stapling is not available on visited host
// NOTICE: OCSP is vulnerable to replay attacks when nonce is not configured on the OCSP responder
// NOTICE: OCSP adds latency (performance)
// NOTICE: Short-lived certificates are not checked for revocation (security.pki.cert_short_lifetime_in_days, default:10)
// CIS Version 1.2.0 October 21st, 2011 2.2.4
//https://github.com/schomery/privacy-settings/issues/40
//https://github.com/pyllyukko/user.js/issues/17
user_pref("security.OCSP.enabled",				1);

// PREF: Enable OCSP Stapling support
// https://en.wikipedia.org/wiki/OCSP_stapling
// https://blog.mozilla.org/security/2013/07/29/ocsp-stapling-in-firefox/
// https://www.digitalocean.com/community/tutorials/how-to-configure-ocsp-stapling-on-apache-and-nginx
user_pref("security.ssl.enable_ocsp_stapling",			true);

// PREF: Enable OCSP Must-Staple support (Firefox >= 45)
// https://blog.mozilla.org/security/2015/11/23/improving-revocation-ocsp-must-staple-and-short-lived-certificates/
// https://www.entrust.com/ocsp-must-staple/
// https://github.com/schomery/privacy-settings/issues/40
// NOTICE: Firefox falls back on plain OCSP when must-staple is not configured on the host certificate
user_pref("security.ssl.enable_ocsp_must_staple",		true);

// PREF: Require a valid OCSP response for OCSP enabled certificates
// https://groups.google.com/forum/#!topic/mozilla.dev.security/n1G-N2-HTVA
// Disabling this will make OCSP bypassable by MitM attacks suppressing OCSP responses
// NOTICE: `security.OCSP.require` will make the connection fail when the OCSP responder is unavailable
// NOTICE: `security.OCSP.require` is known to break browsing on some [captive portals](https://en.wikipedia.org/wiki/Captive_portal)
user_pref("security.OCSP.require",				true);
//user_pref("security.OCSP.require", false);

// PREF: Disable TLS Session Tickets
// https://www.blackhat.com/us-13/briefings.html#NextGen
// https://media.blackhat.com/us-13/US-13-Daigniere-TLS-Secrets-Slides.pdf
// https://media.blackhat.com/us-13/US-13-Daigniere-TLS-Secrets-WP.pdf
// https://bugzilla.mozilla.org/show_bug.cgi?id=917049
// https://bugzilla.mozilla.org/show_bug.cgi?id=967977
user_pref("security.ssl.disable_session_identifiers",		true);

// PREF: Only allow TLS 1.[0-3]
// http://kb.mozillazine.org/Security.tls.version.*
// 1 = TLS 1.0 is the minimum required / maximum supported encryption protocol. (This is the current default for the maximum supported version.)
// 2 = TLS 1.1 is the minimum required / maximum supported encryption protocol.
user_pref("security.tls.version.min",				1);
user_pref("security.tls.version.max",				4);

// PREF: Disable insecure TLS version fallback
// https://bugzilla.mozilla.org/show_bug.cgi?id=1084025
// https://github.com/pyllyukko/user.js/pull/206#issuecomment-280229645
user_pref("security.tls.version.fallback-limit",		3);

// PREF: Enfore Public Key Pinning
// https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning
// https://wiki.mozilla.org/SecurityEngineering/Public_Key_Pinning
// "2. Strict. Pinning is always enforced."
user_pref("security.cert_pinning.enforcement_level",		2);

// PREF: Disallow SHA-1
// https://bugzilla.mozilla.org/show_bug.cgi?id=1302140
// https://shattered.io/
user_pref("security.pki.sha1_enforcement_level",		1);

// PREF: Warn the user when server doesn't support RFC 5746 ("safe" renegotiation)
// https://wiki.mozilla.org/Security:Renegotiation#security.ssl.treat_unsafe_negotiation_as_broken
// https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2009-3555
user_pref("security.ssl.treat_unsafe_negotiation_as_broken",	true);

// PREF: Disallow connection to servers not supporting safe renegotiation (disabled)
// https://wiki.mozilla.org/Security:Renegotiation#security.ssl.require_safe_negotiation
// https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2009-3555
// TODO: `security.ssl.require_safe_negotiation` is more secure but makes browsing next to impossible (2012-2014-... - `ssl_error_unsafe_negotiation` errors), so is left disabled
//user_pref("security.ssl.require_safe_negotiation",		true);

// PREF: Disable automatic reporting of TLS connection errors
// https://support.mozilla.org/en-US/kb/certificate-pinning-reports
// we could also disable security.ssl.errorReporting.enabled, but I think it's
// good to leave the option to report potentially malicious sites if the user
// chooses to do so.
// you can test this at https://pinningtest.appspot.com/
user_pref("security.ssl.errorReporting.automatic",		false);

// PREF: Pre-populate the current URL but do not pre-fetch the certificate in the "Add Security Exception" dialog
// http://kb.mozillazine.org/Browser.ssl_override_behavior
// https://github.com/pyllyukko/user.js/issues/210
user_pref("browser.ssl_override_behavior",			1);

/******************************************************************************
 * SECTION: Cipher suites                                                     *
 ******************************************************************************/

// PREF: Disable null ciphers
user_pref("security.ssl3.rsa_null_sha",				false);
user_pref("security.ssl3.rsa_null_md5",				false);
user_pref("security.ssl3.ecdhe_rsa_null_sha",		false);
user_pref("security.ssl3.ecdhe_ecdsa_null_sha",		false);
user_pref("security.ssl3.ecdh_rsa_null_sha",		false);
user_pref("security.ssl3.ecdh_ecdsa_null_sha",		false);

// PREF: Disable SEED cipher
// https://en.wikipedia.org/wiki/SEED
user_pref("security.ssl3.rsa_seed_sha",				false);

// PREF: Disable 40/56/128-bit ciphers
// 40-bit ciphers
user_pref("security.ssl3.rsa_rc4_40_md5",			false);
user_pref("security.ssl3.rsa_rc2_40_md5",			false);
// 56-bit ciphers
user_pref("security.ssl3.rsa_1024_rc4_56_sha",			false);
// 128-bit ciphers
user_pref("security.ssl3.rsa_camellia_128_sha",			false);
user_pref("security.ssl3.ecdhe_rsa_aes_128_sha",		false);
user_pref("security.ssl3.ecdhe_ecdsa_aes_128_sha",		false);
user_pref("security.ssl3.ecdh_rsa_aes_128_sha",			false);
user_pref("security.ssl3.ecdh_ecdsa_aes_128_sha",		false);
user_pref("security.ssl3.dhe_rsa_camellia_128_sha",		false);
user_pref("security.ssl3.dhe_rsa_aes_128_sha",			false);

// PREF: Disable RC4
// https://developer.mozilla.org/en-US/Firefox/Releases/38#Security
// https://bugzilla.mozilla.org/show_bug.cgi?id=1138882
// https://rc4.io/
// https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2566
user_pref("security.ssl3.ecdh_ecdsa_rc4_128_sha",		false);
user_pref("security.ssl3.ecdh_rsa_rc4_128_sha",			false);
user_pref("security.ssl3.ecdhe_ecdsa_rc4_128_sha",		false);
user_pref("security.ssl3.ecdhe_rsa_rc4_128_sha",		false);
user_pref("security.ssl3.rsa_rc4_128_md5",				false);
user_pref("security.ssl3.rsa_rc4_128_sha",				false);
user_pref("security.tls.unrestricted_rc4_fallback",		false);

// PREF: Disable 3DES (effective key size is < 128)
// https://en.wikipedia.org/wiki/3des#Security
// http://en.citizendium.org/wiki/Meet-in-the-middle_attack
// http://www-archive.mozilla.org/projects/security/pki/nss/ssl/fips-ssl-ciphersuites.html
user_pref("security.ssl3.dhe_dss_des_ede3_sha",			false);
user_pref("security.ssl3.dhe_rsa_des_ede3_sha",			false);
user_pref("security.ssl3.ecdh_ecdsa_des_ede3_sha",		false);
user_pref("security.ssl3.ecdh_rsa_des_ede3_sha",		false);
user_pref("security.ssl3.ecdhe_ecdsa_des_ede3_sha",		false);
user_pref("security.ssl3.ecdhe_rsa_des_ede3_sha",		false);
user_pref("security.ssl3.rsa_des_ede3_sha",			false);
user_pref("security.ssl3.rsa_fips_des_ede3_sha",		false);

// PREF: Disable ciphers with ECDH (non-ephemeral)
user_pref("security.ssl3.ecdh_rsa_aes_256_sha",			false);
user_pref("security.ssl3.ecdh_ecdsa_aes_256_sha",		false);

// PREF: Disable 256 bits ciphers without PFS
user_pref("security.ssl3.rsa_camellia_256_sha",			false);

// PREF: Enable ciphers with ECDHE and key size > 128bits
user_pref("security.ssl3.ecdhe_rsa_aes_256_sha",		true); // 0xc014
user_pref("security.ssl3.ecdhe_ecdsa_aes_256_sha",		true); // 0xc00a

// PREF: Enable GCM ciphers (TLSv1.2 only)
// https://en.wikipedia.org/wiki/Galois/Counter_Mode
user_pref("security.ssl3.ecdhe_ecdsa_aes_128_gcm_sha256",	true); // 0xc02b
user_pref("security.ssl3.ecdhe_rsa_aes_128_gcm_sha256",		true); // 0xc02f

// PREF: Enable ChaCha20 and Poly1305 (Firefox >= 47)
// https://www.mozilla.org/en-US/firefox/47.0/releasenotes/
// https://tools.ietf.org/html/rfc7905
// https://bugzilla.mozilla.org/show_bug.cgi?id=917571
// https://bugzilla.mozilla.org/show_bug.cgi?id=1247860
// https://cr.yp.to/chacha.html
user_pref("security.ssl3.ecdhe_ecdsa_chacha20_poly1305_sha256",	true);
user_pref("security.ssl3.ecdhe_rsa_chacha20_poly1305_sha256",	true);

// PREF: Disable ciphers susceptible to the logjam attack
// https://weakdh.org/
user_pref("security.ssl3.dhe_rsa_camellia_256_sha",		false);
user_pref("security.ssl3.dhe_rsa_aes_256_sha",			false);

// PREF: Disable ciphers with DSA (max 1024 bits)
user_pref("security.ssl3.dhe_dss_aes_128_sha",			false);
user_pref("security.ssl3.dhe_dss_aes_256_sha",			false);
user_pref("security.ssl3.dhe_dss_camellia_128_sha",		false);
user_pref("security.ssl3.dhe_dss_camellia_256_sha",		false);

// PREF: Fallbacks due compatibility reasons
user_pref("security.ssl3.rsa_aes_256_sha",			true); // 0x35
user_pref("security.ssl3.rsa_aes_128_sha",			true); // 0x2f
