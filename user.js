/******************************************************************************
 * My user.js file for FF              |               ye, i know it's messy. *
 * Originally from https://github.com/pyllyukko/user.js                       *
 * It breaks too much stuff for me so I'm adding/removing stuff for my        *
 * purposes. I removed a some of the comments too, to make it readable.       *
 * Date: 2017-09-09                                                           *
 * Please notify me if there are any dupes and suggestions.                   *
 ******************************************************************************/
/*******************************************************************************
 findbar.modalHighlight = true
 findbar.highlightAll = true
 ******************************************************************************/

// Fix font rendering
// https://github.com/renkun-ken/MacType.Source/blob/master/README.md

//user_pref("gfx.font_loader.delay",  											-1);
user_pref("gfx.font_rendering.cleartype.always_use_for_content",				true);
user_pref("gfx.font_rendering.cleartype_params.cleartype_level",				100);
user_pref("gfx.font_rendering.cleartype_params.enhanced_contrast",  			100);
user_pref("gfx.font_rendering.cleartype_params.gamma",  						1400);
user_pref("gfx.font_rendering.cleartype_params.pixel_structure",				1);
user_pref("gfx.font_rendering.cleartype_params.rendering_mode", 				5);
user_pref("gfx.font_rendering.fallback.always_use_cmaps",						true);
user_pref("gfx.use_text_smoothing_setting", 									true);

// probably due to my system local being jp, the font loading is in a disarry.
// this is a temporary fix, until i figure out how this thingy works
user_pref("font.default.x-unicode", "sans-serif");
user_pref("font.default.x-western", "sans-serif");
user_pref("font.internaluseonly.changed", false);
user_pref("font.name.monospace.ja", "Consolas");
user_pref("font.name.monospace.x-western", "Consolas");
user_pref("font.name.sans-serif.ja", "Arial");
user_pref("font.name.sans-serif.x-unicode", "Arial");
user_pref("font.name.sans-serif.x-western", "Arial");
user_pref("font.name.serif.ja", "Arial");
user_pref("font.name.serif.x-unicode", "Arial");
user_pref("font.name.serif.x-western", "Arial");

// https://wiki.mozilla.org/Platform/GFX/HardwareAcceleration
// https://www.macromedia.com/support/documentation/en/flashplayer/help/help01.html
// https://github.com/dillbyrne/random-agent-spoofer/issues/74
user_pref("gfx.direct2d.disabled",					true);
user_pref("layers.acceleration.disabled",			true);

user_pref("browser.altClickSave",			true);
// user_pref("security.nocertdb",			true);

// disables scan for plugins
user_pref("plugin.scan.plid.all",			false);
user_pref("app.update.auto",				false);
user_pref("accessibility.typeaheadfind",			true);

user_pref("geo.wifi.uri",				"");
user_pref("geo.wifi.logging.enabled",		false);
user_pref("browser.newtabpage.directory.source",				"");

user_pref("media.autoplay.enabled",			false);
user_pref("media.ffmpeg.enabled",			false);
user_pref("media.block-autoplay-until-in-foreground",			true);

// disable serviceworkers 
user_pref("dom.serviceWorkers.enabled",			false);
user_pref("dom.serviceWorkers.openWindow.enabled",			false);

user_pref("media.gmp-eme-adobe.enabled",			false);
// user_pref("media.gmp-eme-adobe.version",			"");

user_pref("media.gmp-widevinecdm.enabled",				false);
// user_pref("media.gmp-widevinecdm.version",			"");
// user_pref("media.benchmark.vp9.threshold,			64);

user_pref("breakpad.reportURL",			"");
user_pref("security.ssl.errorReporting.url",			"");
user_pref("experiments.manifest.uri",					"");
user_pref("toolkit.telemetry.cachedClientID",			"");
user_pref("toolkit.telemetry.server",					"");
user_pref("toolkit.telemetry.archive.enabled",			false);
user_pref("services.sync.telemetry.submissionInterval",			99999999);

user_pref("browser.tabs.crashReporting.sendReport",						false);
user_pref("browser.crashReports.unsubmittedCheck.enabled",				false);
user_pref("browser.crashReports.unsubmittedCheck.autoSubmit",			false);

// https://archive.is/r62re
// https://hacks.mozilla.org/2016/03/a-webassembly-milestone/
// https://bugzilla.mozilla.org/show_bug.cgi?id=1278635
user_pref("javascript.options.wasm",				false);
user_pref("javascript.options.wasm_baselinejit", 	false);

// Disable DRM content
// https://wiki.mozilla.org/Media/EME
user_pref("media.eme.enabled",				false);

// https://developer.mozilla.org/en-US/docs/Mozilla/Projects/Social_API
user_pref("social.whitelist",				"");
user_pref("social.directories",				"");
user_pref("social.shareDirectory",				"");
user_pref("social.activeProviders",				"");
user_pref("social.enabled", 						false);
user_pref("social.remote-install.enabled",				false);
user_pref("social.toast-notifications.enabled",				false);
user_pref("social.share.activationPanelEnabled",				false);


user_pref("browser.search.update",				false);
user_pref("browser.urlbar.userMadeSearchSuggestionsChoice",				false);
user_pref("browser.urlbar.doubleClickSelectsAll",				false);
user_pref("browser.urlbar.suggest.searches",				false);
user_pref("browser.urlbar.suggest.bookmark",				true);
user_pref("browser.urlbar.suggest.history",				true);
user_pref("browser.urlbar.suggest.openpage",				true);

user_pref("browser.search.countryCode",				"");
user_pref("browser.search.region",				"");

// uitours
user_pref("browser.onboarding.notification.max-prompt-count-per-tour",		0);
user_pref("browser.onboarding.newtour",		"");
user_pref("browser.onboarding.notification.tour-ids-queue",		"");

/******************************************************************************
 * HTML5 / APIs / DOM                                                         *
 *                                                                            *
 ******************************************************************************/

// disable Location-Aware Browsing
// http://www.mozilla.org/en-US/firefox/geolocation/
user_pref("geo.enabled",					false);
// should i? user_pref("browser.search.geoSpecificDefaults",					false);

// Disable dom.mozTCPSocket.enabled (raw TCP socket support)
// https://trac.torproject.org/projects/tor/ticket/18863
// https://www.mozilla.org/en-US/security/advisories/mfsa2015-97/
// https://developer.mozilla.org/docs/Mozilla/B2G_OS/API/TCPSocket
user_pref("dom.mozTCPSocket.enabled",				false);

// Whether JS can get information about the network/browser connection
// Network Information API provides general information about the system's connection type (WiFi, cellular, etc.)
// https://developer.mozilla.org/en-US/docs/Web/API/Network_Information_API
// https://wicg.github.io/netinfo/#privacy-considerations
// https://bugzilla.mozilla.org/show_bug.cgi?id=960426
user_pref("dom.netinfo.enabled",				false);

// Disable Web Audio API
// https://bugzil.la/1288359
user_pref("dom.webaudio.enabled",				false);

// Don't reveal your internal IP
// Check the settings with: http://net.ipcalf.com/
// https://wiki.mozilla.org/Media/WebRTC/Privacy
user_pref("media.peerconnection.ice.default_address_only",			true); // Firefox < 51
user_pref("media.peerconnection.ice.no_host",			true); // Firefox >= 51
// Disable WebRTC entirely
user_pref("media.peerconnection.enabled",			false);

// https://redd.it/2uaent
user_pref("media.getusermedia.screensharing.allowed_domains",			"");
user_pref("media.peerconnection.video.enabled",			false);
user_pref("media.peerconnection.turn.disable",			true);
user_pref("media.peerconnection.use_document_iceservers",			false);
user_pref("media.peerconnection.identity.enabled",			false);
user_pref("media.peerconnection.identity.timeout",			1);.

// getUserMedia
// https://wiki.mozilla.org/Media/getUserMedia
// https://developer.mozilla.org/en-US/docs/Web/API/Navigator
user_pref("media.navigator.enabled",				false);
// https://developer.mozilla.org/en-US/docs/Web/API/BatteryManager
user_pref("dom.battery.enabled",				false);
// https://wiki.mozilla.org/WebAPI/Security/WebTelephony
user_pref("dom.telephony.enabled",				false);
// https://developer.mozilla.org/en-US/docs/Web/API/navigator.sendBeacon
user_pref("beacon.enabled",					false);
// https://developer.mozilla.org/en-US/docs/Mozilla/Preferences/Preference_reference/dom.event.clipboardevents.enabled
user_pref("dom.event.clipboardevents.enabled",			false);
// https://wiki.mozilla.org/Security/Reviews/Firefox/NavigationTimingAPI
user_pref("dom.enable_performance",				false);

// Speech recognition
// https://dvcs.w3.org/hg/speech-api/raw-file/tip/speechapi.html
// https://wiki.mozilla.org/HTML5_Speech_API
user_pref("media.webspeech.recognition.enable",			false);

// Disable getUserMedia screen sharing
// https://mozilla.github.io/webrtc-landing/gum_test.html
user_pref("media.getusermedia.screensharing.enabled",		false);

// Disable sensor API
// https://wiki.mozilla.org/Sensor_API
user_pref("device.sensors.enabled",				false);

// http://kb.mozillazine.org/Browser.send_pings
user_pref("browser.send_pings",					false);
// this shouldn't have any effect, since we block pings altogether, but we'll set it anyway.
// http://kb.mozillazine.org/Browser.send_pings.require_same_host
user_pref("browser.send_pings.require_same_host",		true);

// Disable gamepad input
// http://www.w3.org/TR/gamepad/
user_pref("dom.gamepad.enabled",				false);

// Disable virtual reality devices
// https://developer.mozilla.org/en-US/Firefox/Releases/36#Interfaces.2FAPIs.2FDOM
user_pref("dom.vr.enabled",					false);

// disable notifications
user_pref("dom.push.enabled",			false);
user_pref("dom.push.connection.enabled",			false);
user_pref("dom.webnotifications.enabled",			false);
user_pref("dom.webnotifications.serviceworker.enabled",		false);

// disable webGL
// http://www.contextis.com/resources/blog/webgl-new-dimension-browser-exploitation/
user_pref("webgl.disabled",					true);
// https://bugzilla.mozilla.org/show_bug.cgi?id=1171228
// https://developer.mozilla.org/en-US/docs/Web/API/WEBGL_debug_renderer_info
user_pref("webgl.enable-debug-renderer-info",			false);
// somewhat related...
user_pref("pdfjs.enableWebGL",				false);


/******************************************************************************
 * Misc                                                                       *
 *                                                                            *
 ******************************************************************************/

// Disable face detection by default
user_pref("camera.control.face_detection.enabled",		false);

// http://kb.mozillazine.org/Clipboard.autocopy
user_pref("clipboard.autocopy",					false);

// Don't trim HTTP off of URLs in the address bar.
// https://bugzilla.mozilla.org/show_bug.cgi?id=665580
user_pref("browser.urlbar.trimURLs",				false);

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

// https://bugzil.la/654550
// https://github.com/pyllyukko/user.js/issues/9#issuecomment-100468785
// https://github.com/pyllyukko/user.js/issues/9#issuecomment-148922065
user_pref("media.video_stats.enabled",				false);

// Don't reveal build ID
// Value taken from Tor Browser
// https://bugzil.la/583181
user_pref("general.buildID.override",				"20100101");


/******************************************************************************
 * extensions / plugins                                                       *
 *                                                                            *
 ******************************************************************************/

// Require signatures
user_pref("xpinstall.signatures.required",				true);

// Opt-out of add-on metadata updates
// https://blog.mozilla.org/addons/how-to-opt-out-of-add-on-metadata-updates/
user_pref("extensions.getAddons.cache.enabled",				false);

// Flash plugin state - never activate
user_pref("plugin.state.flash",				0);
user_pref("plugin.state.java",				0);

// disable Gnome Shell Integration
user_pref("plugin.state.libgnome-shell-browser-plugin",		0);

// disable the bundled OpenH264 video codec
// http://forums.mozillazine.org/viewtopic.php?p=13845077&sid=28af2622e8bd8497b9113851676846b1#p13845077
user_pref("media.gmp-provider.enabled",		false);

// https://wiki.mozilla.org/Firefox/Click_To_Play
// https://blog.mozilla.org/security/2012/10/11/click-to-play-plugins-blocklist-style/
user_pref("plugins.click_to_play",				true);

// http://kb.mozillazine.org/Extensions.blocklist.enabled
user_pref("extensions.blocklist.enabled",			true);

/******************************************************************************
 * firefox features / components                                              *
 *                                                                            *
 ******************************************************************************/

// WebIDE
// https://trac.torproject.org/projects/tor/ticket/16222
user_pref("devtools.webide.enabled",				false);
user_pref("devtools.webide.autoinstallADBHelper",		false);
user_pref("devtools.webide.autoinstallFxdtAdapters",		false);

// disable remote debugging
// https://developer.mozilla.org/docs/Tools/Remote_Debugging/Debugging_Firefox_Desktop#Enable_remote_debugging
// https://developer.mozilla.org/en-US/docs/Tools/Tools_Toolbox#Advanced_settings
user_pref("devtools.debugger.remote-enabled",			false);
// "to use developer tools in the context of the browser itself, and not only web content"
user_pref("devtools.chrome.enabled",				false);
// https://developer.mozilla.org/en-US/docs/Tools/Remote_Debugging/Debugging_Firefox_Desktop#Firefox_37_onwards
user_pref("devtools.debugger.force-local",			true);

// https://wiki.mozilla.org/Platform/Features/Telemetry
// https://www.mozilla.org/en-US/legal/privacy/firefox.html#telemetry
// https://wiki.mozilla.org/Security/Reviews/Firefox6/ReviewNotes/telemetry
// https://gecko.readthedocs.org/en/latest/toolkit/components/telemetry/telemetry/preferences.html
// https://wiki.mozilla.org/Telemetry/Experiments
user_pref("toolkit.telemetry.enabled",				false);
user_pref("toolkit.telemetry.unified",				false);
user_pref("experiments.supported",				false);
user_pref("experiments.enabled",				false);

// Disable the UITour backend so there is no chance that a remote page
// can use it to confuse Tor Browser users.
user_pref("browser.uitour.enabled",				false);

// Resist fingerprinting via window.screen and CSS media queries and other techniques
// https://bugzil.la/418986
// https://bugzil.la/1281949
// https://bugzil.la/1281963
user_pref("privacy.resistFingerprinting",			true);

// Disable the built-in PDF viewer (CVE-2015-2743)
// https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-2743
user_pref("pdfjs.disabled",					true);

// Disable sending of the health report
// https://support.mozilla.org/en-US/kb/firefox-health-report-understand-your-browser-perf
// https://gecko.readthedocs.org/en/latest/toolkit/components/telemetry/telemetry/preferences.html
user_pref("datareporting.healthreport.uploadEnabled",		false);
user_pref("datareporting.healthreport.service.enabled",		false);
user_pref("datareporting.policy.dataSubmissionEnabled",		false);

// Disable new tab tile ads & preload
// http://www.thewindowsclub.com/disable-remove-ad-tiles-from-firefox
// http://forums.mozillazine.org/viewtopic.php?p=13876331#p13876331
user_pref("browser.newtabpage.enhanced",			false);
user_pref("browser.newtab.preload",				false);
// https://wiki.mozilla.org/Tiles/Technical_Documentation#Ping
// https://gecko.readthedocs.org/en/latest/browser/browser/DirectoryLinksProvider.html#browser-newtabpage-directory-ping
user_pref("browser.newtabpage.directory.ping",			"");
// https://gecko.readthedocs.org/en/latest/browser/browser/DirectoryLinksProvider.html#browser-newtabpage-directory-source
//user_pref("browser.newtabpage.directory.source",		"data:text/plain,{}");

// disable heartbeat
// https://wiki.mozilla.org/Advocacy/heartbeat
user_pref("browser.selfsupport.url",				"");

// Disable firefox hello
// https://wiki.mozilla.org/Loop
user_pref("loop.enabled",		false);
// https://groups.google.com/d/topic/mozilla.dev.platform/nyVkCx-_sFw/discussion
user_pref("loop.logDomains",					false);

// CIS 2.3.4 Block Reported Web Forgeries
// http://kb.mozillazine.org/Browser.safebrowsing.enabled
// http://kb.mozillazine.org/Safe_browsing
// https://support.mozilla.org/en-US/kb/how-does-phishing-and-malware-protection-work
// http://forums.mozillazine.org/viewtopic.php?f=39&t=2711237&p=12896849#p12896849
user_pref("browser.safebrowsing.enabled",			false);

// CIS 2.3.5 Block Reported Attack Sites
// http://kb.mozillazine.org/Browser.safebrowsing.malware.enabled
user_pref("browser.safebrowsing.malware.enabled",		false);

// Disable safe browsing remote lookups for downloaded files.
// This leaks information to google.
// https://www.mozilla.org/en-US/firefox/39.0/releasenotes/
// https://wiki.mozilla.org/Security/Application_Reputation
user_pref("browser.safebrowsing.downloads.remote.enabled",	false);
user_pref("browser.safebrowsing.downloads.remote.block_dangerous",	false);
user_pref("browser.safebrowsing.downloads.remote.block_dangerous_host",	false);
user_pref("browser.safebrowsing.downloads.remote.block_uncommon",	false);
user_pref("browser.safebrowsing.downloads.enabled",	false);

// https://support.mozilla.org/en-US/kb/save-web-pages-later-pocket-firefox
user_pref("browser.pocket.enabled",				false);
user_pref("extensions.pocket.enabled",				false);
user_pref("extensions.pocket.api",				"");
user_pref("extensions.pocket.site",				"");

/******************************************************************************
 * automatic connections                                                      *
 *                                                                            *
 ******************************************************************************/

// Disable link prefetching
// http://kb.mozillazine.org/Network.prefetch-next
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Link_prefetching_FAQ#Is_there_a_preference_to_disable_link_prefetching.3F
user_pref("network.prefetch-next",				false);

// https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections#w_geolocation-for-default-search-engine
user_pref("browser.search.geoip.url",				"");

// http://kb.mozillazine.org/Network.dns.disablePrefetch
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Controlling_DNS_prefetching
user_pref("network.dns.disablePrefetch",			true);
user_pref("network.dns.disablePrefetchFromHTTPS",		true);

// https://bugzilla.mozilla.org/show_bug.cgi?id=1228457
user_pref("network.dns.blockDotOnion",				true);

// https://wiki.mozilla.org/Privacy/Reviews/Necko
user_pref("network.predictor.enabled",				false);

// https://wiki.mozilla.org/Privacy/Reviews/Necko#Principle:_Real_Choice
user_pref("network.seer.enabled",				false);

// Disable SSDP
// https://bugzil.la/1111967
user_pref("browser.casting.enabled",				false);

// https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections#w_media-capabilities
// http://andreasgal.com/2014/10/14/openh264-now-in-firefox/
user_pref("media.gmp-gmpopenh264.enabled",			false);
user_pref("media.gmp-manager.url",				"");

// https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections#w_speculative-pre-connections
// https://bugzil.la/814169
user_pref("network.http.speculative-parallel-limit",		0);

// https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections#w_mozilla-content
user_pref("browser.aboutHomeSnippets.updateUrl",		"");

// https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections#w_auto-update-checking
user_pref("browser.search.update",				false);

/******************************************************************************
 * HTTP                                                                       *
 *                                                                            *
 ******************************************************************************/

// Disallow NTLMv1
// https://bugzilla.mozilla.org/show_bug.cgi?id=828183
user_pref("network.negotiate-auth.allow-insecure-ntlm-v1",	false);

// https://bugzilla.mozilla.org/show_bug.cgi?id=855326
user_pref("security.csp.experimentalEnabled",			true);

// CSP https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Introducing_Content_Security_Policy
user_pref("security.csp.enable",				true);

// Subresource integrity
// https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
// https://wiki.mozilla.org/Security/Subresource_Integrity
user_pref("security.sri.enable",				true);

// https://support.mozilla.org/en-US/questions/973320
// https://developer.mozilla.org/en-US/docs/Mozilla/Preferences/Preference_reference/browser.pagethumbnails.capturing_disabled
user_pref("browser.pagethumbnails.capturing_disabled",		true);

/******************************************************************************
 * UI related                                                                 *
 *                                                                            *
 ******************************************************************************/

// CIS Version 1.2.0 October 21st, 2011 2.1.2 Enable Auto Notification of Outdated Plugins
// https://wiki.mozilla.org/Firefox3.6/Plugin_Update_Awareness_Security_Review
user_pref("plugins.update.notifyUser",				true);

// CIS Version 1.2.0 October 21st, 2011 2.1.3 Enable Information Bar for Outdated Plugins
user_pref("plugins.hide_infobar_for_outdated_plugin",		false);

// CIS Mozilla Firefox 24 ESR v1.0.0 - 3.6 Enable IDN Show Punycode
// http://kb.mozillazine.org/Network.IDN_show_punycode
user_pref("network.IDN_show_punycode",				true);

// http://www.labnol.org/software/browsers/prevent-firefox-showing-bookmarks-address-location-bar/3636/
// http://kb.mozillazine.org/Browser.urlbar.maxRichResults
// "Setting the preference to 0 effectively disables the Location Bar dropdown entirely."
user_pref("browser.urlbar.maxRichResults",			20);

// https://blog.mozilla.org/security/2010/03/31/plugging-the-css-history-leak/
// http://dbaron.org/mozilla/visited-privacy
user_pref("layout.css.visited_links_enabled",			false);

user_pref("browser.urlbar.autocomplete.enabled",		true);

// http://kb.mozillazine.org/Signon.autofillForms
// https://www.torproject.org/projects/torbrowser/design/#identifier-linkability
user_pref("signon.autofillForms",				false);

// do not check if firefox is the default browser
user_pref("browser.shell.checkDefaultBrowser",			false);

/******************************************************************************
 * TLS / HTTPS / OCSP related stuff                                           *
 *                                                                            *
 ******************************************************************************/

// https://blog.mozilla.org/security/2012/11/01/preloading-hsts/
// https://wiki.mozilla.org/Privacy/Features/HSTS_Preload_List
user_pref("network.stricttransportsecurity.preloadlist",	true);

// CIS Version 1.2.0 October 21st, 2011 2.2.4 Enable Online Certificate Status Protocol
user_pref("security.OCSP.enabled",				1);

// https://blog.mozilla.org/security/2013/07/29/ocsp-stapling-in-firefox/
user_pref("security.ssl.enable_ocsp_stapling",			true);

// require certificate revocation check through OCSP protocol.
// NOTICE: this leaks information about the sites you visit to the CA.
// user_pref("security.OCSP.require",				true);
user_pref("security.OCSP.require",				false);

// https://www.blackhat.com/us-13/briefings.html#NextGen
// https://media.blackhat.com/us-13/US-13-Daigniere-TLS-Secrets-Slides.pdf
// https://media.blackhat.com/us-13/US-13-Daigniere-TLS-Secrets-WP.pdf
// https://bugzil.la/917049
// https://bugzil.la/967977
user_pref("security.ssl.disable_session_identifiers",		true);

// TLS 1.[012]
// http://kb.mozillazine.org/Security.tls.version.max
// 1 = TLS 1.0 is the minimum required / maximum supported encryption protocol. (This is the current default for the maximum supported version.)
// 2 = TLS 1.1 is the minimum required / maximum supported encryption protocol.
user_pref("security.tls.version.min",				1);
user_pref("security.tls.version.max",				3);

// pinning
// https://wiki.mozilla.org/SecurityEngineering/Public_Key_Pinning#How_to_use_pinning
// "2. Strict. Pinning is always enforced."
user_pref("security.cert_pinning.enforcement_level",		2);


// https://wiki.mozilla.org/Security:Renegotiation#security.ssl.treat_unsafe_negotiation_as_broken
// see also CVE-2009-3555
user_pref("security.ssl.treat_unsafe_negotiation_as_broken",	true);

// https://support.mozilla.org/en-US/kb/certificate-pinning-reports
//
// we could also disable security.ssl.errorReporting.enabled, but I think it's
// good to leave the option to report potentially malicious sites if the user
// chooses to do so.
//
// you can test this at https://pinningtest.appspot.com/
user_pref("security.ssl.errorReporting.automatic",		false);

// http://kb.mozillazine.org/Browser.ssl_override_behavior
// Pre-populate the current URL but do not pre-fetch the certificate.
user_pref("browser.ssl_override_behavior",			1);

/******************************************************************************
 * CIPHERS                                                                    *
 *                                                                            *
 * you can debug the SSL handshake with tshark:                               *
 *     tshark -t ad -n -i wlan0 -T text -V -R ssl.handshake                   *
 ******************************************************************************/

// disable null ciphers
user_pref("security.ssl3.rsa_null_sha",				false);
user_pref("security.ssl3.rsa_null_md5",				false);
user_pref("security.ssl3.ecdhe_rsa_null_sha",			false);
user_pref("security.ssl3.ecdhe_ecdsa_null_sha",			false);
user_pref("security.ssl3.ecdh_rsa_null_sha",			false);
user_pref("security.ssl3.ecdh_ecdsa_null_sha",			false);

// SEED
// https://en.wikipedia.org/wiki/SEED
user_pref("security.ssl3.rsa_seed_sha",				false);

// 40 bits...
user_pref("security.ssl3.rsa_rc4_40_md5",			false);
user_pref("security.ssl3.rsa_rc2_40_md5",			false);

// 56 bits
user_pref("security.ssl3.rsa_1024_rc4_56_sha",			false);

// 128 bits
user_pref("security.ssl3.rsa_camellia_128_sha",			false);
user_pref("security.ssl3.ecdhe_rsa_aes_128_sha",		false);
user_pref("security.ssl3.ecdhe_ecdsa_aes_128_sha",		false);
user_pref("security.ssl3.ecdh_rsa_aes_128_sha",			false);
user_pref("security.ssl3.ecdh_ecdsa_aes_128_sha",		false);
user_pref("security.ssl3.dhe_rsa_camellia_128_sha",		false);
user_pref("security.ssl3.dhe_rsa_aes_128_sha",			false);

// RC4 (CVE-2013-2566)
user_pref("security.ssl3.ecdh_ecdsa_rc4_128_sha",		false);
user_pref("security.ssl3.ecdh_rsa_rc4_128_sha",			false);
user_pref("security.ssl3.ecdhe_ecdsa_rc4_128_sha",		false);
user_pref("security.ssl3.ecdhe_rsa_rc4_128_sha",		false);
user_pref("security.ssl3.rsa_rc4_128_md5",			false);
user_pref("security.ssl3.rsa_rc4_128_sha",			false);
// https://developer.mozilla.org/en-US/Firefox/Releases/38#Security
// https://bugzil.la/1138882
// https://rc4.io/
user_pref("security.tls.unrestricted_rc4_fallback",		false);

// 3DES -> false because effective key size < 128
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

// Ciphers with ECDH (without /e$/)
user_pref("security.ssl3.ecdh_rsa_aes_256_sha",			false);
user_pref("security.ssl3.ecdh_ecdsa_aes_256_sha",		false);

// 256 bits without PFS
user_pref("security.ssl3.rsa_camellia_256_sha",			false);

// Ciphers with ECDHE and > 128bits
user_pref("security.ssl3.ecdhe_rsa_aes_256_sha",		true);
user_pref("security.ssl3.ecdhe_ecdsa_aes_256_sha",		true);

// GCM, yes please!
user_pref("security.ssl3.ecdhe_ecdsa_aes_128_gcm_sha256",	true);
user_pref("security.ssl3.ecdhe_rsa_aes_128_gcm_sha256",		true);

// ChaCha20 and Poly1305. Supported since Firefox 47.
// https://www.mozilla.org/en-US/firefox/47.0/releasenotes/
// https://tools.ietf.org/html/rfc7905
// https://bugzil.la/917571
// https://bugzil.la/1247860
// https://cr.yp.to/chacha.html
user_pref("security.ssl3.ecdhe_ecdsa_chacha20_poly1305_sha256",	true);
user_pref("security.ssl3.ecdhe_rsa_chacha20_poly1305_sha256",	true);

// Susceptible to the logjam attack - https://weakdh.org/
user_pref("security.ssl3.dhe_rsa_camellia_256_sha",		false);
user_pref("security.ssl3.dhe_rsa_aes_256_sha",			false);

// Ciphers with DSA (max 1024 bits)
user_pref("security.ssl3.dhe_dss_aes_128_sha",			false);
user_pref("security.ssl3.dhe_dss_aes_256_sha",			false);
user_pref("security.ssl3.dhe_dss_camellia_128_sha",		false);
user_pref("security.ssl3.dhe_dss_camellia_256_sha",		false);

// Fallbacks due compatibility reasons
user_pref("security.ssl3.rsa_aes_256_sha",			true);
user_pref("security.ssl3.rsa_aes_128_sha",			true);
