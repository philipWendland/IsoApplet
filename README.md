General Information
===================
The Java Card IsoApplet (e.g. for use with OpenSC).
The Applet is capable of saving a PKCS#15 file structure and performing PKI related operations using the private key, such as signing or decrypting.
Private keys can be generated directly on the smartcard or imported from the host computer.
The import of private keys is disabled in the default security configuration.
The applet targets mordern Smartcards with Java Card 2.2.2 or above.

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
* Perform `git submodule init && git submodule update` to retrieve the ant-javacard source code.
* *Optional*: Download a suitable Java Card SDK (e.g. version 2.2.2) and adjust the path in build.xml:
  For ant-javacard to recognize the Java Card SDK you can either set the `JC_HOME` environment variable, modify the javacard task in the build.xml (`<javacard jckit="/path/to/jckit">`), or set `jc.home`.
  See the [ant-javacard documentation](https://github.com/martinpaljak/ant-javacard#building-javacard-applet-cap-files-with-ant) for more details.
* Install Apache `ant`, `openjdk-8-jdk`
* Invoke `ant` to produce the cap file.
  This will also compile ant-javacard when invoked for the first time.

Installation
============
Install the CAP-file (IsoApplet.cap) to your Java Card smartcard (e.g. with [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro)).
