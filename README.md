## Firefox customization stuff
This repository contains some files to make Firefox customization less painful.

### user.js
Required readings: 

http://kb.mozillazine.org/User.js_file

The most popular way of setting advanced preferences. The file in this repository is a very watered down version of [pyllyukko's user.js](https://github.com/pyllyukko/user.js) (for my convenience). You should definitely check out the original. 

### Global Preferences
Required readings: 

https://developer.mozilla.org/en-US/Firefox/Enterprise_deployment

Namely the `mozilla.cfg` and `autoconfig.js` files in the repository. You must know what every single preference you put in there does. Otherwise you're in for a lot of unwanted surprises. Best practice would be to get used to using `user.js` first and then attempt to set global preferences.

### userChrome.css and userContent.css
Required readings: 

http://kb.mozillazine.org/index.php?title=UserChrome.css

http://kb.mozillazine.org/UserContent.css

It is used to apply styles to the browser itself. Mostly used to enforce themes.


#### userscripts

https://en.wikipedia.org/wiki/Userscript

This repository also contains a few userscripts that can be used to apply styles to websites. 

To use them, you will need a script manager first. I recommend using Greasemonkey or Violentmonkey. Regardless of what of you use, make sure that it's open-source.
