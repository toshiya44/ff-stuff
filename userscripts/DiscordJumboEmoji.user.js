// ==UserScript==
// @name          Discord Jumbo Emojis
// @author        Toshiya
// @description   Make emojis bigger in Discord
// @namespace     https://github.com/toshiya44/ff-stuff/
// @include       https://discordapp.com/channels/*
// @version       1.0
// @grant         none
// @icon           data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAMAAACdt4HsAAAAqFBMVEUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAs30iGAAAAN3RSTlMA8gnbvAb4JOfAWE5DyFQ94yoYpoB5SDcTxJdnYTEg0s6soot8dbOOhwyemh2ScG1e1motDrfpa9avJgAAAo1JREFUWMPt1lmP2jAUBeBjZ983CCQQtmHfB2Z6//8/q+MguSAQ085DpZbvIUdRZN34Ph28/LPOeKh7yf7cxQ1/zrQ6xhhQ/XHraJA+UY1E7OQ5c2AEIt/MYIIb49mZi3DamGoc4EEYoxZpG3MqsoAwpDwcAz6LvBDXDP2TzYAwMIy4A6DVwwC1jFguIlkCqGz7MBdfnUPV6+FaSIUH8LjD22sIxeW+W9O26txH9Z+3snF9HZtrZolrjvylGdswSiBM0qVT5zIwx77IzACgWUda1tftzka4wTiEKdntIeRBtpZ/oK+sbC6ylFPQtev75Uzf4kbVbMLneHn5m940qY0HskqGNccDQ/IHwgcesFcywjXu42TiWzpU4FtOtIMUzlp67ukbAH7mlCka+7BJ3ZDhZfqui1+taZ8KwMbOmK2PyMKCsgXT+OVgJMN6bzZulgum3+zQjuNYA0Z9tB1wkx/JA1zxkFizQ3cCIaUesGDXO7y8Goxj0kcyhDYHkFBfTa5H7+UblcBHeneHVQAMExzXzdGIPDVZcCIZS9IOq/s77JXgDNidjpTUu6OtmqxugsHC1D6ud3iEtOmj4wBFp03deuLozg6tuAP45F3vMIE0OuOwABjvUQR45EL6oXZYn62AXJ5QO6TWVIgMZmDi4jxCasft0nzD1Q4XBwipGcze2A5Quq1G1T0B/RRJCKzcWX+LRpg16VoyrF67l+CrrJRbhYs/5xDRBN+wzfMBXv5zZ1Urv4wPgQCqc6pa2S01CvDUMYA/h+qcqlae7Lwy8FTh5UUE1TlVrXyPmRnhGZ+IAqjOqWplTrq7wlN65i08qM6paqU+9solntKBjQHVOVWtLOJlZOArXp3z5Xf9BD3bOPviZ3u1AAAAAElFTkSuQmCC
// ==/UserScript==

function addDiscordStyle(css) {
    var head, style;
    head = document.getElementsByTagName('head')[0];
    if (!head) { return; }
    style = document.createElement('style');
    style.type = 'text/css';
    style.innerHTML = css;
    head.appendChild(style);
}
addDiscordStyle('img[src*="/emojis/"].emoji{min-height: 2.8em !important;  min-width: 3.2em !important;} img[src*="/emojis/"].emoji.jumboable{min-height: 6.2em !important;  min-width: 6.8em !important;} img[src*="/assets/"].emoji{max-height: 0.8em !important; max-width: 1em !important; width: auto; height: auto} img[src*="/assets/"].emoji.jumboable{max-height: 1em !important; max-width: 1em !important; width: auto; height: auto}');
