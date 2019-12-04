General Information
===================
The Java Card IsoApplet (e.g. for use with OpenSC).
The Applet is capable of saving a PKCS#15 file structure and performing PKI related operations using the private key, such as signing or decrypting.
Private keys can be generated directly on the smart card or imported from the host computer.
The import of private keys is disabled in the default security configuration.
The applet targets modern Smartcards with Java Card 2.2.2 or above.

**Have a look at the wiki for more information:** https://github.com/philipWendland/IsoApplet/wiki

Smartcard requirements
======================
* Java Card version 2.2.2 or above
* Implementation of the "requestObjectDeletion()"-mechanism of the Java Card API is recommended to be able to properly delete files.
* Support of javacardx.apdu.ExtendedLength if extended APDUs are to be used
* Support of javacardx.crypto.Cipher
* Support of FP ECC with the corresponding field size if ECDSA is to be used

Build process
=============
This project uses [ant-javacard](https://github.com/martinpaljak/ant-javacard) to build cap-files.
After cloning the IsoApplet repository, all you have to do is:
* Perform `git submodule init && git submodule update` to retrieve the Java Card SDKs, in case you did not `git clone --recursive` to clone this repository.
* Install Apache `ant`, `openjdk-11-jdk-headless`
* Invoke `ant` to produce the cap file.

Installation
============
Install the CAP-file (IsoApplet.cap) to your Java Card smart card (e.g. with [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro)).
