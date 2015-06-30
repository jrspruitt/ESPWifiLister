# esp_wifi_lister
esp8266 wifi module firmware that attempts to list over uart all wifi devices, ap and stations, in the area.

Uses [esp-open-sdk](https://github.com/pfalcon/esp-open-sdk)

**Makefile**

* Make sure OPENSDK points to your esp-open-sdk directory
* ESPTOOL point to the esptool directory.

**Compile**

* Hook up the wifi module for esptool and run _make flash run_ to compile, upload and, start.
