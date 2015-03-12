General Information
===================
The Java Card IsoApplet (e.g. for use with OpenSC).
The Applet is capable of saving a PKCS#15 file structure and performing PKI related operations using the private key, such as signing or decrypting.
Private keys can be generated directly on the smartcard or imported from the host computer.
The import of private keys is disabled in the default security configuration.
The Applet targets mordern Smartcards with Java Card 2.2.2 or above.


**For more information please visit:** http://www.pwendland.net/IsoApplet

Requirements
============
There are several requirements that have to be fulfilled in order to build, install or use the 
applet.

Smartcard requirements
----------------------
* Java Card version 2.2.2 or above
* Implementation of the "requestObjectDeletion()"-mechanism of the Java Card API is recommended to be able to properly delete files.
* Support of javacardx.apdu.ExtendedLength if extended APDUs are to be used
* Support of javacardx.crypto.Cipher
* Support of FP ECC with the corresponding field size if ECDSA is to be used

Build requirements
------------------
* Java Card SDK 2.2.2, the environment variable JC_HOME must be properly set. Building with newer versions is untested.
* ant with Java Card ant-tasks (the "jctasks.jar" file, i.e. copy $JC_HOME/ant-tasks/lib/jctasks.jar to $ANT_HOME/lib)

Build process
=============
The simple ant build script can be used, just invoke:
```
$ ant
```

Clean
=====
To clean the directory, invoke:
```
$ ant clean
```

Installation
============
Load the CAP-file from the "dist"-directory onto your Java Card (e.g. with GPShell).
