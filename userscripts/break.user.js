// ==UserScript==
// @name          Break
// @description   Breaks long words.
// @author        Toshiya
// @version       0.0.1
// @namespace     https://github.com/toshiya44
// @include       http://example.com/*
// @include       https://example.com/*
// @grant         none
// ==/UserScript==
function addGlobalStyle(css) {
    var head, style;
    head = document.getElementsByTagName('head')[0];
    if (!head) { return; }
    style = document.createElement('style');
    style.type = 'text/css';
    style.innerHTML = css;
    head.appendChild(style);
}
addGlobalStyle('*{overflow-wrap: break-word !important;} /*td>a.tag{display:none;}*/');
