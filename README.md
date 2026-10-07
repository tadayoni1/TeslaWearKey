TeslaWearKey
===

An app for Android Wear that allows the user to use their WearOS watch to unlock, lock, and drive supported Tesla vehicles.

Based on HCE, ,the watch emulates as a Tesla Key Card to interact with the vehicle.

---
### Features
* Unlock / Lock your Tesla Model 3 or Y.
* Key generated and used inside Android KeyStore (StrongBox when available); the private key never leaves secure hardware
* Only answers the car while the watch is unlocked, and only while the app is open or for 30 seconds after leaving it
* No internet access or bluetooth required
* Based on Tesla Key Card protocol

### Dependencies
* NFC-enabled WearOS watch running Wear OS 4 or later (Android 12 / API 31+)
* A screen lock (PIN or pattern) set up on the watch
* Tested on following devices
  * Pixel Watch 2 (Android 15, wearOS 5.1)
  * Galaxy Watch 6 Classic (Android 14, wearOS 5.0, BXK1)
  * Galaxy Watch 6 (Android 14, wearOS 5.0, BYD1)


### Usage Guide
* Enable Developer mode on your watch
* Connect to watch via ADB
* Side-load apk file found in releases via ADB
* Use existing key card to load watch in the vehicle system
* Test extensively to ensure watch works effectively.
* TIP: The side of the Galaxy Watches contains the NFC antenna.
* TIP 2: Open the app before tapping. The key works while the app is open and for 30 seconds after you leave it (e.g. when the screen turns off as you tilt your wrist).
* Upgrading from 1.4.2 or earlier creates a new key: remove the old watch key in the car and enroll the watch again with your key card.

### Download link

<a href='https://play.google.com/store/apps/details?id=li.power.app.wearos.teslanak'><img alt='Get it on Google Play' height='80' src='https://play.google.com/intl/en_us/badges/images/generic/en_badge_web_generic.png'/></a>

* [Release Page](https://github.com/pccr10001/TeslaWearKey/releases)

### References
* [GaussKeyCard](https://github.com/darconeous/gauss-key-card)
* [TKC Protocol](https://gist.github.com/darconeous/2cd2de11148e3a75685940158bddf933) by [@darconeous](https://github.com/darconeous)

### Contributors
* @pccr10001
* @nzjjay
* @felipefc10

### Support me
[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/pwrli)
