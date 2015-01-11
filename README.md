General Information
===================
The Java Card IsoApplet (e.g. for use with the corresponding OpenSC-fork).
The Applet is capable of saving a PKCS#15 file structure and performing PKI related operations 
using the private key, such as signing or decrypting. Also, on-card generation of asymmetric 
key-pairs is the only way to get usable private keys onto the smartcard.
The Applet targets mordern Smartcards. Anything below Java Card 2.2.2 is untested.


**For more information please visit:** http://www.pwendland.net/IsoApplet

Requirements
============
There are several requirements that have to be fulfilled in order to build, install or use the 
applet.

Smartcard requirements
----------------------
* Java Card 2.2.2 or above (>= 3.0.1 recommended) 
* Implementation of the "requestObjectDeletion()"-mechanism to properly delete files
  (My JCOP 2.4.1 card can do this, but it is unclear whether any JCOP 2.4.1 card is capable.)
* Support of javacardx.apdu.ExtendedLength if extended APDUs are to be used
* Support of javacardx.crypto.Cipher
* Support of FP ECC if ECDSA is to be used (field lengths of 192 and 256 Bit are supported)

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
