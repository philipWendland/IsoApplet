# General Information
The Java Card IsoApplet (e.g. for use with OpenSC).
The Applet is capable of saving a PKCS#15 file structure and performing PKI related operations using the private key, such as signing or decrypting.
Private keys can be generated directly on the smart card or imported from the host computer.
The import of private keys is disabled in the default security configuration.
The applet targets modern smartcards with Java Card 3.0.4 or above.

# IsoApplet Version and Smartcard requirements
IsoApplet is maintained in two different versions: one for newer smartcards and a legacy version for older smartcards.
If your smartcard supports the newer version of IsoApplet, you should prefer it.
For both versions, the support of the "requestObjectDeletion()"-mechanism of the Java Card API is recommended to be able to properly delete files.
Also, the javacardx.crypto.Cipher-package needs to be supported by your smart card.
This is very common among Java Card smartcards.

## New version of IsoApplet (v1)
This version is found on the [main branch](https://github.com/philipWendland/IsoApplet/tree/main).
It targets smartcards with Java Card version >= 3.0.4.
This version requires extended APDUs the be used and supported by your reader and smartcard (javacardx.apdu.ExtendedLength).
It is not recommended to use smart cards that do not support the object deletion mechanism (JCSystem.isObjectDeletionSupported()), but all Java Cards version >= 3.0.4 should support it.
If supported by your smart card, the newer version of IsoApplet supports the following additional features:
* RSA keys of 4096 bit length
* RSA PSS signatures
* ECDSA with off-card hashing, which makes ECC actually usable in practice

## Legacy Version of IsoApplet (v0)
The legacy version is found on the [main-javacard-v2.2.2 branch](https://github.com/philipWendland/IsoApplet/tree/main-javacard-v2.2.2) branch.
It targets smartcards with Java Card version >= 2.2.2.
The ECDSA implementation with Java Card version 2.2.2 is hardly usable in practice because it requires on-card hash generation.
If your smartcard implements javacardx.apdu.ExtendedLength and IsoApplet is configured with `DEF_EXT_APDU` in `IsoApplet.java`, you can use extended APDUs.

# Build process
This project uses [ant-javacard](https://github.com/martinpaljak/ant-javacard) to build cap-files.
After cloning the IsoApplet repository, all you have to do is:
* Perform `git submodule init && git submodule update` to retrieve the Java Card SDKs, in case you did not `git clone --recursive` to clone this repository.
* Install Apache `ant`, `openjdk-17-jdk-headless`
* If needed, configure the correct Java SDK version or set the JAVA_HOME environment variable.
* Invoke `ant` to produce the cap file.
If you have build errors on an existing repository, try deleting the ant-javacard.jar file so that the newest version is downloaded.

# Installation
Install the CAP-file (IsoApplet.cap) to your Java Card smart card (e.g. with [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro)).

## Installation parameters
IsoApplet accepts optional installation parameters (the applet specific parameters of the INSTALL command, tag C9).
They are a sequence of TLV entries (one byte tag, one byte length, value), each of them optional and allowed once.
With GlobalPlatformPro, they are passed as hexadecimal string using `--params`.

| Tag | Length | Value | Meaning |
|-----|--------|-------|---------|
| `80` | `01` | `00` (default, also if the tag is not given) | Probe whether the smart card supports RSA keys of 4096 bit length. |
| `80` | `01` | `01` | Do not probe. The RSA 4096 feature bit is not set in the features byte (GET DATA `0101`), so clients such as OpenSC do not use 4096 bit RSA keys. This does not block the key operations themselves: if the smart card supports 4096 bit RSA, a client that requests it anyway is still served. |
| `80` | `01` | `02` | Do not probe. The RSA 4096 feature bit is set in the features byte. Only use this if your smart card supports RSA keys of 4096 bit length. Otherwise, generating or importing such keys fails with SW 6A81 (function not supported). |

Other values, unknown tags, repeated tags and malformed TLV data are rejected and the installation fails (IsoApplet throws SW 6A80, but the status word reported by the card's installer may differ).
Rejecting unknown tags ensures that a setting is never silently ignored, for example by an older version of IsoApplet.

On some smart cards, probing for RSA 4096 support takes so long that the installation times out:
The INSTALL command gets no response, GlobalPlatformPro reports e.g. `Invalid argument: newPosition < 0: (-2 < 0)`,
and `gp -l` lists the IsoApplet package, but no applet instance.
In this case, install with tag `80` set to `01` or `02`, e.g. to skip the probe on a smart card with support for RSA keys of 4096 bit length:
```
gp --install IsoApplet.cap --params 800102
```

**Have a look at the wiki for more information:** https://github.com/philipWendland/IsoApplet/wiki

