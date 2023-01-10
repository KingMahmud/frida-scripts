# frida-scripts

A collection of frida scripts to facilitate reverse engineering of android apps.

Mostly written by me, some parts are taken from other open source scripts. Thanks to the original authors.

* [**Helpers.js**](https://github.com/KingMahmud/frida-scripts/blob/master/Helpers.js). A set of helper/utility for frida scripts.
* [**execve.js**](https://github.com/KingMahmud/frida-scripts/blob/master/execve.js). Tracing * [**execve**](https://man7.org/linux/man-pages/man2/execve.2.html).
* [**mbedtls_cipher.js**](https://github.com/KingMahmud/frida-scripts/blob/master/mbedtls_cipher.js). A tracing script related to * [**Mbed-TLS**](https://github.com/Mbed-TLS/mbedtls).
* [**registerNatives.js**](https://github.com/KingMahmud/frida-scripts/blob/master/registerNatives.js). A script for revealing native methods which were registered using env->registerNatives.
\registerNatives.js : reveals native methods registered with env->registerNatives()
