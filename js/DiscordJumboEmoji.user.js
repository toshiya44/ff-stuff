// ==UserScript==
// @name          Discord Jumbo Emojis
// @author        Toshiya
// @version       0.0.1
// @namespace     https://github.com/toshiya44
// @description   Make emojis bigger in Discord
// @include       https://discordapp.com/*
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
addGlobalStyle('img[src*="/emojis/"].emoji{min-height: 2.8em !important;  min-width: 3.2em !important;} img[src*="/emojis/"].emoji.jumboable{min-height: 6.2em !important;  min-width: 6.8em !important;} img[src*="/assets/"].emoji{max-height: 0.8em !important; max-width: 1em !important; width: auto; height: auto} img[src*="/assets/"].emoji.jumboable{max-height: 1em !important; max-width: 1em !important; width: auto; height: auto}');
