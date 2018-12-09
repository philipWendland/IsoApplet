/*
 * IsoApplet: A Java Card PKI applet aimiing for ISO 7816 compliance.
 * Copyright (C) 2014  Philip Wendland (wendlandphilip@gmail.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

package net.pwendland.javacard.pki.isoapplet;

import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.APDU;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.framework.OwnerPIN;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.Key;
import javacard.security.RSAPublicKey;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.ECKey;
import javacard.security.ECPublicKey;
import javacard.security.ECPrivateKey;
import javacardx.crypto.Cipher;
import javacardx.apdu.ExtendedLength;
import javacard.security.CryptoException;
import javacard.security.Signature;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.KeyAgreement;
import org.globalplatform.GPSystem;

/**
 * \brief The IsoApplet class.
 *
 * This applet has a filesystem and accepts relevant ISO 7816 instructions.
 * Access control is forced through a PIN and a SO PIN. PIN can be unblocked with PUK.
 * The PUK is optional (Set DEF_PUK_MUST_BE_SET). By default PUK is set with SO PIN value.
 * Security Operations are being processed directly in this class.
 * Only private keys are stored as Key-objects. Only security
 * operations with private keys can be performed (decrypt with RSA, sign with RSA,
 * sign with ECDSA).
 *
 * \author Philip Wendland
 */
public class IsoApplet extends Applet implements ExtendedLength {
    /* API Version */
    public static final byte API_VERSION_MAJOR = (byte) 0x00;
    public static final byte API_VERSION_MINOR = (byte) 0x07;

    /* Card-specific configuration */
    public static final boolean DEF_EXT_APDU = false;
    public static final boolean DEF_PRIVATE_KEY_IMPORT_ALLOWED = false;
    public static final boolean DEF_PUK_MUST_BE_SET = false;
    public static final byte DEF_PIN_MAX_TRIES = 3;
    public static final byte DEF_PIN_MAX_LENGTH = 12;
    public static final byte DEF_PUK_LENGTH = 12;
    public static final byte DEF_SOPIN_LENGTH = 12;

    /* ISO constants not in the "ISO7816" interface */
    // File system related INS:
    public static final byte INS_CREATE_FILE = (byte) 0xE0;
    public static final byte INS_UPDATE_BINARY = (byte) 0xD6;
    public static final byte INS_READ_BINARY = (byte) 0xB0;
    public static final byte INS_DELETE_FILE = (byte) 0xE4;
    // Other INS:
    public static final byte INS_VERIFY = (byte) 0x20;
    public static final byte INS_CHANGE_REFERENCE_DATA = (byte) 0x24;
    public static final byte INS_GENERATE_ASYMMETRIC_KEYPAIR = (byte) 0x46;
    public static final byte INS_RESET_RETRY_COUNTER = (byte) 0x2C;
    public static final byte INS_MANAGE_SECURITY_ENVIRONMENT = (byte) 0x22;
    public static final byte INS_PERFORM_SECURITY_OPERATION = (byte) 0x2A;
    public static final byte INS_GET_RESPONSE = (byte) 0xC0;
    public static final byte INS_PUT_DATA = (byte) 0xDB;
    public static final byte INS_GET_CHALLENGE = (byte) 0x84;
    public static final byte INS_GET_DATA = (byte) 0xCA;
    public static final byte INS_DELETE_KEY = (byte) 0xE5;
    public static final byte INS_INITIALISE_CARD = (byte) 0x51;
    public static final byte INS_ERASE_CARD = (byte) 0x50;
    public static final byte INS_GET_VALUE = (byte) 0x6C;

    // Status words:
    public static final short SW_PIN_TRIES_REMAINING = 0x63C0; // See ISO 7816-4 section 7.5.1
    public static final short SW_COMMAND_NOT_ALLOWED_GENERAL = 0x6900;
    public static final short SW_NO_PIN_DEFINED = (short)0x9802;
    public static final short SW_AUTHENTICATION_METHOD_BLOCKED = 0x6983;

    /* PIN, PUK, SO PIN and key related constants */
    // PIN:
    private static final byte PIN_REF = (byte) 0x01;
    private static final byte PIN_MIN_LENGTH = 4;
    // PUK:
    private static final byte PUK_REF = (byte) 0x02;
    private static final byte PUK_MAX_TRIES = 5;
    // SO PIN:
    private static final byte SOPIN_REF = (byte) 0x0F;
    private static final byte SOPIN_MAX_TRIES = 5;
    // Keys:
    private static final short KEY_MAX_COUNT = 16;

    private static final short DEF_RSA_KEYLEN = KeyBuilder.LENGTH_RSA_2048;

    private static final byte ALG_GEN_RSA = (byte) 0xF3;
    private static final byte ALG_RSA_PAD_PKCS1 = (byte) 0x11;

    private static final byte ALG_GEN_EC = (byte) 0xEC;
    private static final byte ALG_ECDSA_PRECOMPUTED_HASH = (byte) 0x22;
    private static final byte ALG_ECDH = (byte) 0x23;

    private static final short KeyBuilder_LENGTH_RSA_3072 = 3072;

    private static final short LENGTH_EC_FP_224 = 224;
    private static final short LENGTH_EC_FP_256 = 256;
    private static final short LENGTH_EC_FP_320 = 320;
    private static final short LENGTH_EC_FP_384 = 384;
    private static final short LENGTH_EC_FP_512 = 512;
    private static final short LENGTH_EC_FP_521 = 521;

    /* Card/Applet lifecycle states */
    private static final byte STATE_CREATION = (byte) 0x00; // No restrictions, SO PIN not set yet.
    private static final byte STATE_INITIALISATION = (byte) 0x01; // SO PIN set, PIN & PUK not set yet.
    private static final byte STATE_OPERATIONAL_ACTIVATED = (byte) 0x05; // PIN is set, data is secured.
    private static final byte STATE_OPERATIONAL_DEACTIVATED = (byte) 0x04; // Applet usage is deactivated. (Unused at the moment.)
    private static final byte STATE_TERMINATED = (byte) 0x0C; // Applet usage is terminated.

    private static final byte API_FEATURE_EXT_APDU = (byte) 0x01;
    private static final byte API_FEATURE_SECURE_RANDOM = (byte) 0x02;
    private static final byte API_FEATURE_ECDSA_SHA1 = (byte) 0x04;
    private static final byte API_FEATURE_RSA_4096 = (byte) 0x08;
    private static final byte API_FEATURE_ECDSA_PRECOMPUTED_HASH = (byte) 0x10;
    private static final byte API_FEATURE_ECDH = (byte) 0x20;

    /* Other constants */
    // "ram_buf" is used for:
    //	* GET RESPONSE (caching for response APDUs):
    //		- GENERATE ASYMMETRIC KEYPAIR: RSA >= 1024 bit and ECC >= 256 bit public key information.
    //	* Command Chaining or extended APDUs (caching of command APDU data):
    //		- DECIPHER (RSA >= 1024 bit).
    //		- GENERATE ASYMMETRIC KEYPAIR: ECC curve parameters if large (> 256 bit) prime fields are used.
    //		- PUT DATA: RSA and ECC private key import.
    private static final short RAM_BUF_SIZE_2048 = (short) 664;
    // 4096bit RSA needs larger buffer which is not available on some cards
    private static final short RAM_BUF_SIZE_4096 = (short) 1310;

    // "ram_chaining_cache" is used for:
    //		- Caching of the amount of bytes remainung.
    //		- Caching of the current send position.
    //		- Determining how many operations had previously been performed in the chain (re-use CURRENT_POS)
    //		- Caching of the current INS (Only one chain at a time, for one specific instruction).
    private static final short RAM_CHAINING_CACHE_SIZE = (short) 4;
    private static final short RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING = (short) 0;
    private static final short RAM_CHAINING_CACHE_OFFSET_CURRENT_POS = (short) 1;
    private static final short RAM_CHAINING_CACHE_OFFSET_CURRENT_INS = (short) 2;
    private static final short RAM_CHAINING_CACHE_OFFSET_CURRENT_P1P2 = (short) 3;

    /* Member variables: */
    private byte state;
    private IsoFileSystem fs = null;
    private OwnerPIN pin = null;
    private OwnerPIN puk = null;
    private OwnerPIN sopin = null;
    private byte[] currentAlgorithmRef = null;
    private short[] currentPrivateKeyRef = null;
    private Key[] keys = null;
    private byte[] ram_buf = null;
    private short[] ram_chaining_cache = null;
    private Cipher rsaPkcs1Cipher = null;
    private Signature ecdsaSignaturePrecomp = null;
    private boolean ecdsaSHA512;
    private RandomData randomData = null;
    private KeyAgreement ecdh = null;
    private byte api_features;
    private short ram_buf_size = RAM_BUF_SIZE_2048;
    private byte pin_max_tries = DEF_PIN_MAX_TRIES;
    private boolean puk_must_be_set = DEF_PUK_MUST_BE_SET;
    private boolean private_key_import_allowed = DEF_PRIVATE_KEY_IMPORT_ALLOWED;
    private byte pin_max_length = DEF_PIN_MAX_LENGTH;
    private byte puk_length = DEF_PUK_LENGTH;
    private byte sopin_length = DEF_SOPIN_LENGTH;
    private byte histBytes[] = null;
    private boolean puk_is_set = false;
    private byte transport_key[] = null;
    private byte serial[] = null;
    private short initCounter = 0;


    /**
     * \brief Installs this applet.
     *
     * \param bArray
     *			the array containing installation parameters
     * \param bOffset
     *			the starting offset in bArray
     * \param bLength
     *			the length in bytes of the parameter data in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new IsoApplet(bArray, bOffset, bLength);
    }

    /**
     * \brief Only this class's install method should create the applet object.
     */
    protected IsoApplet(byte[] bArray, short bOffset, byte bLength) {
        api_features = 0;

        // Find parameters offset (La) in bArray
        byte li, lc, la;
        short bOff;
        // Find parameters offset (la) in bArray
        li = bArray[bOffset];
        lc = bArray[(short)(bOffset + li + 1)];
        la = bArray[(short)(bOffset + li + lc + 2)];
        bOff = (short)(bOffset + li + lc + 3);
        setDefaultValues(bArray, bOff, la, true);
        pin = new OwnerPIN(pin_max_tries, pin_max_length);
        puk = new OwnerPIN(PUK_MAX_TRIES, puk_length);
        sopin = new OwnerPIN(SOPIN_MAX_TRIES, sopin_length);
        fs = new IsoFileSystem();
        try {
            Key prKey = KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_CRT_PRIVATE, KeyBuilder.LENGTH_RSA_4096, false);
            prKey = null;
            api_features |= API_FEATURE_RSA_4096;
            ram_buf_size = RAM_BUF_SIZE_4096;
        } catch (CryptoException e) {
            ram_buf_size = RAM_BUF_SIZE_2048;
        }
        ram_buf = JCSystem.makeTransientByteArray(ram_buf_size, JCSystem.CLEAR_ON_DESELECT);

        ram_chaining_cache = JCSystem.makeTransientShortArray(RAM_CHAINING_CACHE_SIZE, JCSystem.CLEAR_ON_DESELECT);

        if (transport_key != null) {
            sopin.update(transport_key, (short) 0, sopin_length);
            sopin.resetAndUnblock();
            Util.arrayFillNonAtomic(transport_key, (short) 0, sopin_length, (byte) 0x00);
        }

        currentAlgorithmRef = JCSystem.makeTransientByteArray((short)1, JCSystem.CLEAR_ON_DESELECT);
        currentPrivateKeyRef = JCSystem.makeTransientShortArray((short)1, JCSystem.CLEAR_ON_DESELECT);
        keys = new Key[KEY_MAX_COUNT];

        currentPrivateKeyRef[0] = -1;

        rsaPkcs1Cipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);

        /* Some 3.0.4 cards support Signature.SIG_CIPHER_ECDSA which can sign arbitrary long input data,
         * cards that don't support this can still sign max 64 bytes of data using ALG_ECDSA_SHA_512 and
         * Signature.signPreComputedHash() */
        try {
            ecdsaSignaturePrecomp = Signature.getInstance(MessageDigest.ALG_NULL, Signature.SIG_CIPHER_ECDSA, Cipher.PAD_NULL, false);
            ecdsaSHA512 = false;
        } catch (Exception e) {
            ecdsaSignaturePrecomp = null;
        }
        if (ecdsaSignaturePrecomp == null) {
            try {
                ecdsaSignaturePrecomp = Signature.getInstance(Signature.ALG_ECDSA_SHA_512, false);
                ecdsaSHA512 = true;
            } catch (Exception e) {
                ecdsaSignaturePrecomp = null;
            }
        }
        if (ecdsaSignaturePrecomp != null) {
            api_features |= API_FEATURE_ECDSA_PRECOMPUTED_HASH;
        } else {
            api_features &= ~API_FEATURE_ECDSA_PRECOMPUTED_HASH;
        }

        try {
            randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
            api_features |= API_FEATURE_SECURE_RANDOM;
        } catch (CryptoException e) {
            if(e.getReason() == CryptoException.NO_SUCH_ALGORITHM) {
                randomData = null;
                api_features &= ~API_FEATURE_SECURE_RANDOM;
            } else {
                throw e;
            }
        }

        try {
            ecdh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
            api_features |= API_FEATURE_ECDH;
        } catch (Exception e) {
            ecdh = null;
            api_features &= ~API_FEATURE_ECDH;
        }

        if(DEF_EXT_APDU) {
            api_features |= API_FEATURE_EXT_APDU;
        }

        state = STATE_CREATION;
        register();
    }

    /**
     * \brief This method is called whenever the applet is being deselected.
     */
    public void deselect() {
        pin.reset();
        puk.reset();
        sopin.reset();
        fs.setUserAuthenticated(false);
    }

    /**
     * \brief This method is called whenever the applet is being selected.
     */
    public boolean select() {
        if(state == STATE_CREATION
                || state == STATE_INITIALISATION) {
            fs.setUserAuthenticated(SOPIN_REF);
        } else {
            fs.setUserAuthenticated(false);
        }
        // Reset file selection state
        fs.selectFile(null);
        return true;
    }

    /**
     * \brief Processes an incoming APDU.
     *
     * \see APDU.
     *
     * \param apdu The incoming APDU.
     */
    public void process(APDU apdu) {
        byte buffer[] = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];

        if (state == STATE_TERMINATED) {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }

        // Return the API version if we are being selected.
        // Format:
        //  - byte 0: Major version
        //  - byte 1: Minor version
        //  - byte 2: Feature bitmap (used to distinguish between applet features)
        if(selectingApplet()) {
            // setATRHistBytes can't be invoked from constructor, so do it here.
            if (histBytes != null) {
                try {
                    if (GPSystem.setATRHistBytes(histBytes, (short) 0, (byte) histBytes.length)) {
                        histBytes = null;
                    }
                } catch (Exception e) {
                    // silently ignore error
                }
            }
            buffer[0] = API_VERSION_MAJOR;
            buffer[1] = API_VERSION_MINOR;
            buffer[2] = api_features;
            apdu.setOutgoingAndSend((short) 0, (short) 3);
            return;
        }

        // No secure messaging at the moment
        if(apdu.isSecureMessagingCLA()) {
            ISOException.throwIt(ISO7816.SW_SECURE_MESSAGING_NOT_SUPPORTED);
        }

        // Command chaining checks
        if(ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_INS] != 0 || isCommandChainingCLA(apdu)) {
            short p1p2 = Util.getShort(buffer, ISO7816.OFFSET_P1);
            /*
             * Command chaining only for:
             * 	- PERFORM SECURITY OPERATION
             * 	- GENERATE ASYMMETRIC KEYKAIR
             * 	- PUT DATA
             * when not using extended APDUs.
             */
            if( DEF_EXT_APDU ||
                    (ins != INS_PERFORM_SECURITY_OPERATION
                     && ins != INS_GENERATE_ASYMMETRIC_KEYPAIR
                     && ins != INS_PUT_DATA)) {
                ISOException.throwIt(ISO7816.SW_COMMAND_CHAINING_NOT_SUPPORTED);
            }

            if(ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_INS] == 0
                    && ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_P1P2] == 0) {
                /* A new chain is starting - set the current INS and P1P2. */
                if(ins == 0) {
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                }
                ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_INS] = ins;
                ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_P1P2] = p1p2;
            } else if(ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_INS] != ins
                      || ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_P1P2] != p1p2) {
                /* The current chain is not yet completed,
                 * but an apdu not part of the chain had been received. */
                ISOException.throwIt(SW_COMMAND_NOT_ALLOWED_GENERAL);
            } else if(!isCommandChainingCLA(apdu)) {
                /* A chain is ending, set the current INS and P1P2 to zero to indicate that. */
                ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_INS] = 0;
                ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_P1P2] = 0;
            }
        }

        // If the card expects a GET RESPONSE, no other operation should be requested.
        if(ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING] > 0 && ins != INS_GET_RESPONSE) {
            ISOException.throwIt(SW_COMMAND_NOT_ALLOWED_GENERAL);
        }

        // INS dispatching
        switch(ins) {
            // We use VERIFY apdu with proprietary class byte to bypass pinpad firewalled readers
            case INS_VERIFY:
                processVerify(apdu);
                break;
            // We use CHANGE_REFERENCE_DATA apdu with proprietary class byte for
            // implicit transition from STATE_CREATION to STATE_INITIALISATION
            case INS_CHANGE_REFERENCE_DATA:
                processChangeReferenceData(apdu);
                break;
        }

        if(apdu.isISOInterindustryCLA()) {
            switch (ins) {
            case ISO7816.INS_SELECT:
                fs.processSelectFile(apdu);
                break;
            case INS_READ_BINARY:
                fs.processReadBinary(apdu);
                break;
            case INS_MANAGE_SECURITY_ENVIRONMENT:
                processManageSecurityEnvironment(apdu);
                break;
            case INS_PERFORM_SECURITY_OPERATION:
                processPerformSecurityOperation(apdu);
                break;
            case INS_CREATE_FILE:
                fs.processCreateFile(apdu);
                break;
            case INS_UPDATE_BINARY:
                fs.processUpdateBinary(apdu);
                break;
            case INS_DELETE_FILE:
                fs.processDeleteFile(apdu);
                break;
            case INS_GENERATE_ASYMMETRIC_KEYPAIR:
                processGenerateAsymmetricKeypair(apdu);
                break;
            case INS_RESET_RETRY_COUNTER:
                processResetRetryCounter(apdu);
                break;
            case INS_GET_RESPONSE:
                processGetResponse(apdu);
                break;
            case INS_PUT_DATA:
                processPutData(apdu);
                break;
            case INS_GET_CHALLENGE:
                processGetChallenge(apdu);
                break;
            case INS_GET_DATA:
                processGetData(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            } // switch
        } else {
            switch (ins) {
            case INS_DELETE_KEY:
                processDeleteKey(apdu);
                break;
            case INS_INITIALISE_CARD:
                processInitialiseCard(apdu);
                break;
            case INS_ERASE_CARD:
                processEraseCard(apdu);
                break;
            case INS_GET_VALUE:
                processGetValue(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        }
    }

    /**
     * \brief Parse the apdu's CLA byte to determine if the apdu is the first or second-last part of a chain.
     *
     * The Java Card API version 2.2.2 has a similar method (APDU.isCommandChainingCLA()), but tests have shown
     * that some smartcard platform's implementations are wrong (not according to the JC API specification),
     * specifically, but not limited to, JCOP 2.4.1 R3.
     *
     * \param apdu The apdu.
     *
     * \return true If the apdu is the [1;last[ part of a command chain,
     *			false if there is no chain or the apdu is the last part of the chain.
     */
    static boolean isCommandChainingCLA(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        return ((byte)(buf[0] & (byte)0x10) == (byte)0x10);
    }

    /**
     * \brief Sets default parameters (serial, etc).
     *
     * \param bArray
     *			the array containing installation parameters
     * \param bOffset
     *			the starting offset in bArray
     * \param bLength
     *			the length in bytes of the parameter data in bArray
     * \param init
     *	        TODO
     */
    private void setDefaultValues(byte[] bArray, short bOffset, byte bLength, boolean init) {
        final byte TAG_PIN_MAX_TRIES = (byte)0x01;
        final byte TAG_PUK_MUST_BE_SET = (byte)0x02;
        final byte TAG_ENABLE_KEY_IMPORT = (byte)0x03;
        final byte TAG_PIN_MAX_LENGTH = (byte)0x04;
        final byte TAG_PUK_LENGTH = (byte)0x05;
        final byte TAG_SOPIN_LENGTH = (byte)0x06;
        final byte TAG_HISTBYTES = (byte)0x07;
        final byte TAG_TRANSPORT_KEY = (byte)0x08;
        final byte TAG_SERIAL = (byte)0x09;

        short pos, len;

        if(bLength == 0) {
            // Default parameters
            pin_max_tries = DEF_PIN_MAX_TRIES;
            puk_must_be_set = DEF_PUK_MUST_BE_SET;
            private_key_import_allowed = DEF_PRIVATE_KEY_IMPORT_ALLOWED;
            pin_max_length = DEF_PIN_MAX_LENGTH;
            puk_length = DEF_PUK_LENGTH;
            sopin_length = DEF_SOPIN_LENGTH;
            histBytes = null;
            transport_key = null;
            if (init) {
                serial = new byte[4];
                RandomData.getInstance(RandomData.ALG_SECURE_RANDOM).generateData(serial, (short)0, (short)4);
            }
            return;
        }
        try {
            try {
                pos = UtilTLV.findTag(bArray, bOffset, bLength, TAG_PIN_MAX_TRIES);
                len = UtilTLV.decodeLengthField(bArray, ++pos);
                if(len != 1) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
                pin_max_tries = bArray[++pos];
            } catch (NotFoundException e) {
                pin_max_tries = DEF_PIN_MAX_TRIES;
            }
            try {
                pos = UtilTLV.findTag(bArray, bOffset, bLength, TAG_PUK_MUST_BE_SET);
                len = UtilTLV.decodeLengthField(bArray, ++pos);
                if(len != 1) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
                puk_must_be_set = bArray[++pos] != 0;
            } catch (NotFoundException e) {
                puk_must_be_set = DEF_PUK_MUST_BE_SET;
            }
            try {
                pos = UtilTLV.findTag(bArray, bOffset, bLength, TAG_ENABLE_KEY_IMPORT);
                len = UtilTLV.decodeLengthField(bArray, ++pos);
                if(len != 1) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
                private_key_import_allowed = bArray[++pos] != 0;
            } catch (NotFoundException e) {
                private_key_import_allowed = DEF_PRIVATE_KEY_IMPORT_ALLOWED;
            }
            try {
                pos = UtilTLV.findTag(bArray, bOffset, bLength, TAG_PIN_MAX_LENGTH);
                len = UtilTLV.decodeLengthField(bArray, ++pos);
                if(len != 1) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
                pin_max_length = bArray[++pos];
            } catch (NotFoundException e) {
                pin_max_length = DEF_PIN_MAX_LENGTH;
            }
            try {
                pos = UtilTLV.findTag(bArray, bOffset, bLength, TAG_PUK_LENGTH);
                len = UtilTLV.decodeLengthField(bArray, ++pos);
                if(len != 1) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
                puk_length = bArray[++pos];
            } catch (NotFoundException e) {
                puk_length = DEF_PUK_LENGTH;
            }
            try {
                pos = UtilTLV.findTag(bArray, bOffset, bLength, TAG_HISTBYTES);
                len = UtilTLV.decodeLengthField(bArray, ++pos);
                if(len > 8) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
                histBytes = new byte[len];
                Util.arrayCopyNonAtomic(bArray, ++pos, histBytes, (short) 0, len);
            } catch (NotFoundException e) {
                histBytes = null;
            }
            try {
                pos = UtilTLV.findTag(bArray, bOffset, bLength, TAG_SOPIN_LENGTH);
                len = UtilTLV.decodeLengthField(bArray, ++pos);
                if(len != 1) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
                sopin_length = bArray[++pos];
            } catch (NotFoundException e) {
                sopin_length = DEF_SOPIN_LENGTH;
            }
            try {
                pos = UtilTLV.findTag(bArray, bOffset, bLength, TAG_TRANSPORT_KEY);
                len = UtilTLV.decodeLengthField(bArray, ++pos);
                if(len != sopin_length) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
                transport_key = new byte[len];
                Util.arrayCopyNonAtomic(bArray, ++pos, transport_key, (short) 0, len);
            } catch (NotFoundException e) {
                transport_key = null;
            }
            if (init) {
                try {
                    pos = UtilTLV.findTag(bArray, bOffset, bLength, TAG_SERIAL);
                    len = UtilTLV.decodeLengthField(bArray, ++pos);
                    if(len > 8) {
                        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                    }
                    serial = new byte[len];
                    Util.arrayCopyNonAtomic(bArray, ++pos, serial, (short) 0, len);
                } catch (NotFoundException e) {
                    serial = new byte[4];
                    RandomData.getInstance(RandomData.ALG_SECURE_RANDOM).generateData(serial, (short)0, (short)4);
                }
            }
        } catch (InvalidArgumentsException e) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
    }

    /**
     * \brief Process the VERIFY apdu (INS = 20).
     *
     * This apdu is used to verify a PIN and authenticate the user. A counter is used
     * to limit unsuccessful tries (i.e. brute force attacks).
     *
     * \param apdu The apdu.
     *
     * \throw ISOException SW_INCORRECT_P1P2, ISO7816.SW_WRONG_LENGTH, SW_PIN_TRIES_REMAINING, SW_AUTHENTICATION_METHOD_BLOCKED.
     */
    private void processVerify(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        short offset_cdata;
        short lc;
        byte ref = buf[ISO7816.OFFSET_P2];

        /* P1 FF means logout. */
        if (buf[ISO7816.OFFSET_P1] == (byte)0xFF) {
            pin.reset();
            puk.reset();
            sopin.reset();
            fs.setUserAuthenticated(false);
            return;
        }

        // P1 00 only at the moment. (key-reference 01 = PIN, key-reference 0F = SO PIN)
        if(buf[ISO7816.OFFSET_P1] != 0x00 || (ref != PIN_REF && ref != SOPIN_REF)) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Bytes received must be Lc.
        lc = apdu.setIncomingAndReceive();
        if(lc != apdu.getIncomingLength()) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        offset_cdata = apdu.getOffsetCdata();

        // Lc might be 0, in this case the caller checks if verification is required.
        if (ref == PIN_REF) {
            if((lc > 0 && (lc < PIN_MIN_LENGTH) || lc > pin_max_length)) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
        } else if (ref == SOPIN_REF) {
            if(lc > 0 && lc != sopin_length) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
        }

        // Caller asks if verification is needed.
        if(lc == 0) {
            if (ref == PIN_REF) {
                if (state == STATE_CREATION || state == STATE_INITIALISATION) {
                    ISOException.throwIt(SW_NO_PIN_DEFINED);
                } else if (state == STATE_OPERATIONAL_ACTIVATED) {
                    if( pin.isValidated() ) {
                        return;
                    }
                    ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | pin.getTriesRemaining()));
                } else if (state == STATE_OPERATIONAL_DEACTIVATED) {
                    ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                }
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
            } else if (ref == SOPIN_REF) {
                if (state == STATE_CREATION) {
                    if (transport_key == null || sopin.isValidated()) {
                        // No verification required.
                        return;
                    }
                    ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | sopin.getTriesRemaining()));
                } else if (state == STATE_INITIALISATION || state == STATE_OPERATIONAL_ACTIVATED) {
                    if( sopin.isValidated() ) {
                        return;
                    }
                    ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | sopin.getTriesRemaining()));
                } else if (state == STATE_OPERATIONAL_DEACTIVATED) {
                    ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                }
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
            } else {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
        }

        if (ref == PIN_REF) {
            // Pad the PIN if not done by caller, so no garbage from the APDU will be part of the PIN.
            Util.arrayFillNonAtomic(buf, (short)(offset_cdata + lc), (short)(pin_max_length - lc), (byte) 0x00);

            // Check the PIN.
            if(!pin.check(buf, offset_cdata, pin_max_length)) {
                fs.setUserAuthenticated(false);
                if (pin.getTriesRemaining() > 0)
                    ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | pin.getTriesRemaining()));
                ISOException.throwIt(SW_AUTHENTICATION_METHOD_BLOCKED);
            } else {
                fs.setUserAuthenticated(PIN_REF);
            }
        } else if (ref == SOPIN_REF) {
            // Check the SOPIN.
            if(!sopin.check(buf, offset_cdata, sopin_length)) {
                fs.setUserAuthenticated(false);
                if (sopin.getTriesRemaining() > 0)
                    ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | sopin.getTriesRemaining()));
                if (transport_key != null)
                    state = STATE_TERMINATED;
                ISOException.throwIt(SW_AUTHENTICATION_METHOD_BLOCKED);
            } else {
                fs.setUserAuthenticated(SOPIN_REF);
                if(state == STATE_CREATION && transport_key != null) {
                    // Set PUK (may be re-set during PIN creation)
                    puk.update(buf, offset_cdata, (byte)lc);
                    puk.resetAndUnblock();
                    puk_is_set = true;
                    // Increment init counter
                    if (initCounter < 32677)
                        initCounter++;
                    state = STATE_INITIALISATION;
                }
            }
        } else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    /**
     * \brief Process the CHANGE REFERENCE DATA apdu (INS = 24).
     *
     * If the state is STATE_CREATION, we can set the SO PIN without verification.
     * The state will advance to STATE_INITIALISATION (i.e. the SO PIN must be set before the PIN).
     * In a "later" state the user must authenticate himself to be able to change the PIN.
     *
     * \param apdu The apdu.
     *
     * \throws ISOException SW_INCORRECT_P1P2, ISO7816.SW_WRONG_LENGTH, SW_PIN_TRIES_REMAINING.
     */
    private void processChangeReferenceData(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short lc;
        short offset_cdata;

        // Bytes received must be Lc.
        lc = apdu.setIncomingAndReceive();
        if(lc != apdu.getIncomingLength()) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        offset_cdata = apdu.getOffsetCdata();

        if(state == STATE_CREATION) {
            // We _set_ the SO PIN in this state.
            // Key reference must be 0F (SO PIN). P1 must be 01 because no verification data should be present in this state.
            if(p1 != 0x01 || p2 != SOPIN_REF) {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }

            // We set the SO PIN and advance to STATE_INITIALISATION.

            if (lc == 0) {
                if (transport_key == null) {
                    ISOException.throwIt(SW_NO_PIN_DEFINED);
                }
                // Implicit change to STATE_INITIALISATION as SO PIN has been verified for ERASE_CARD apdu processing
                if (sopin.isValidated()) {
                    // PUK should also be set, as it was cleared in ERASE_CARD, but we don't know the SO PIN
                    // puk.update(buf, offset_cdata, (byte)lc);
                    // puk.resetAndUnblock();
                    // puk_is_set = true;

                    fs.setUserAuthenticated(SOPIN_REF);

                    // Increment init counter
                    if (initCounter < 32677)
                        initCounter++;

                    state = STATE_INITIALISATION;

                    return;
                } else {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }
            }

            // Check length.
            if(lc != sopin_length) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }

            if(transport_key != null && !sopin.check(buf, offset_cdata, (byte) lc)) {
                ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | sopin.getTriesRemaining()));
            }

            // Set SO PIN
            sopin.update(buf, offset_cdata, (byte)lc);
            sopin.resetAndUnblock();
            sopin.check(buf, offset_cdata, (byte) lc);
            fs.setUserAuthenticated(SOPIN_REF);

            // Set PUK (may be re-set during PIN creation)
            puk.update(buf, offset_cdata, (byte)lc);
            puk.resetAndUnblock();
            puk_is_set = true;

            // Increment init counter
            if (initCounter < 32677)
                initCounter++;

            state = STATE_INITIALISATION;
        } else if(state == STATE_INITIALISATION) {
            if(p1 != 0x01) {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
            // We _set_ the PIN (P2=01) or PUK (P2=02)
            if(p2 == PIN_REF) {
                // We are supposed to set the PIN right away - no PUK will be set, ever.
                // This might me forbidden because of security policies:
                if(puk_must_be_set && !puk_is_set) {
                    ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
                }

                // Check the PIN length.
                if(lc < PIN_MIN_LENGTH || lc > pin_max_length) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                // Pad the PIN upon creation, so no garbage from the APDU will be part of the PIN.
                Util.arrayFillNonAtomic(buf, (short)(offset_cdata + lc), (short)(pin_max_length - lc), (byte) 0x00);

                // Set PIN.
                pin.update(buf, offset_cdata, pin_max_length);
                pin.resetAndUnblock();

                state = STATE_OPERATIONAL_ACTIVATED;
            } else if(p2 == PUK_REF) {
                // Check length.
                if(lc != puk_length) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }

                // Set PUK.
                puk.update(buf, offset_cdata, (byte)lc);
                puk.resetAndUnblock();
                puk_is_set = true;
            } else {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }

        } else {
            // P1 must be 00 as the old PIN/SOPIN must be provided, followed by new PIN/SOPIN without delimitation.
            if(p1 != 0x00) {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
            if (p2 == PIN_REF) {
                // We _change_ the PIN (P2=01).
                // Both PINs must already padded (otherwise we can not tell when the old PIN ends.)

                // Check PIN lengths: PINs must be padded, i.e. Lc must be 2*pin_max_length.
                if(lc != (short)(2*pin_max_length)) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }

                // Check the old PIN.
                if(!pin.check(buf, offset_cdata, pin_max_length)) {
                    ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | pin.getTriesRemaining()));
                }

                // UPDATE PIN
                pin.update(buf, (short) (offset_cdata+pin_max_length), pin_max_length);
            } else if (p2 == SOPIN_REF) {
                // We _change_ the SO PIN (P2=0F).

                // Check PIN lengths: PINs must be padded, i.e. Lc must be 2*sopin_length.
                if(lc != (short)(2*sopin_length)) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }

                // Check the old SO PIN.
                if(!sopin.check(buf, offset_cdata, sopin_length)) {
                    ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | sopin.getTriesRemaining()));
                }

                // UPDATE SO PIN
                sopin.update(buf, (short) (offset_cdata+sopin_length), sopin_length);
            } else {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
        }// end if(state == STATE_CREATION)
    }// end processChangeReferenceData()

    /**
     * \brief Process the RESET RETRY COUNTER apdu (INS = 2C).
     *
     * This is used to unblock the PIN with the PUK and set a new PIN value.
     *
     * \param apdu The RESET RETRY COUNTER apdu.
     *
     * \throw ISOException SW_COMMAND_NOT_ALLOWED, ISO7816.SW_WRONG_LENGTH, SW_INCORRECT_P1P2,
     *			SW_PIN_TRIES_REMAINING.
     */
    public void	processResetRetryCounter(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short lc;
        short offset_cdata;

        if(state != STATE_OPERATIONAL_ACTIVATED) {
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }

        // Bytes received must be Lc.
        lc = apdu.setIncomingAndReceive();
        if(lc != apdu.getIncomingLength()) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        offset_cdata = apdu.getOffsetCdata();

        // Length of data field.
        if(lc < (short)(puk_length + PIN_MIN_LENGTH)
                || lc > (short)(puk_length + pin_max_length)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // We expect the PUK followed by a new PIN.
        if(p1 != (byte) 0x00 || p2 != PIN_REF) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Check the PUK.
        if(!puk.check(buf, offset_cdata, puk_length)) {
            ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | puk.getTriesRemaining()));
        }

        // If we're here, the PUK was correct.
        // Pad the new PIN, if not done by caller. We don't want any gargabe from the APDU buffer to be part of the new PIN.
        Util.arrayFillNonAtomic(buf, (short)(offset_cdata + lc), (short)(puk_length + pin_max_length - lc), (byte) 0x00);

        // Set the PIN.
        pin.update(buf, (short)(offset_cdata+puk_length), pin_max_length);
        pin.resetAndUnblock();
    }

    /**
     * \brief Initialize an EC key with the curve parameters from buf.
     *
     * \param buf The buffer containing the EC curve parameters. It must be TLV with the following format:
     * 				81 - prime
     * 				82 - coefficient A
     * 				83 - coefficient B
     * 				84 - base point G
     * 				85 - order
     * 				87 - cofactor
     *
     * \param bOff The offset at where the first entry is located.
     *
     * \param bLen The remaining length of buf.
     *
     * \param key The EC key to initialize.
     *
     * \throw NotFoundException Parts of the data needed to fully initialize
     *                          the key were missing.
     *
     * \throw InvalidArgumentsException The ASN.1 sequence was malformatted.
     */
    private void initEcParams(byte[] buf, short bOff, short bLen, ECKey key) throws NotFoundException, InvalidArgumentsException {
        short pos = bOff;
        short len;

        /* Search for the prime */
        pos = UtilTLV.findTag(buf, bOff, bLen, (byte) 0x81);
        pos++;
        len = UtilTLV.decodeLengthField(buf, pos);
        pos += UtilTLV.getLengthFieldLength(len);
        key.setFieldFP(buf, pos, len); // "p"

        /* Search for coefficient A */
        pos = UtilTLV.findTag(buf, bOff, bLen, (byte) 0x82);
        pos++;
        len = UtilTLV.decodeLengthField(buf, pos);
        pos += UtilTLV.getLengthFieldLength(len);
        key.setA(buf, pos, len);

        /* Search for coefficient B */
        pos = UtilTLV.findTag(buf, bOff, bLen, (byte) 0x83);
        pos++;
        len = UtilTLV.decodeLengthField(buf, pos);
        pos += UtilTLV.getLengthFieldLength(len);
        key.setB(buf, pos, len);

        /* Search for base point G */
        pos = UtilTLV.findTag(buf, bOff, bLen, (byte) 0x84);
        pos++;
        len = UtilTLV.decodeLengthField(buf, pos);
        pos += UtilTLV.getLengthFieldLength(len);
        key.setG(buf, pos, len); // G(x,y)

        /* Search for order */
        pos = UtilTLV.findTag(buf, bOff, bLen, (byte) 0x85);
        pos++;
        len = UtilTLV.decodeLengthField(buf, pos);
        pos += UtilTLV.getLengthFieldLength(len);
        key.setR(buf, pos, len); // Order of G - "q"

        /* Search for cofactor */
        pos = UtilTLV.findTag(buf, bOff, bLen, (byte) 0x87);
        pos++;
        len = UtilTLV.decodeLengthField(buf, pos);
        pos += UtilTLV.getLengthFieldLength(len);
        if(len == 2) {
            key.setK(Util.getShort(buf, pos));
        } else if(len == 1) {
            key.setK(buf[pos]);
        } else {
            throw InvalidArgumentsException.getInstance();
        }
    }

    /**
     * \brief Process the GENERATE ASYMMETRIC KEY PAIR apdu (INS = 46).
     *
     * A MANAGE SECURITY ENVIRONMENT must have succeeded earlier to set parameters for key
     * generation.
     *
     * \param apdu The apdu.
     *
     * \throw ISOException SW_WRONG_LENGTH, SW_INCORRECT_P1P2, SW_CONDITIONS_NOT_SATISFIED,
     *			SW_SECURITY_STATUS_NOT_SATISFIED.
     */
    public void processGenerateAsymmetricKeypair(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short privKeyRef = currentPrivateKeyRef[0];
        short lc;
        KeyPair kp = null;
        ECPrivateKey privKey = null;
        ECPublicKey pubKey = null;

        if( ! pin.isValidated() ) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        switch(currentAlgorithmRef[0]) {
        case ALG_GEN_RSA:
            if(p1 != (byte) 0x42 || p2 != (byte) 0x00) {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }

            // Bytes received must be Lc.
            lc = apdu.setIncomingAndReceive();
            if(lc != apdu.getIncomingLength()) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            short offset_cdata = apdu.getOffsetCdata();

            /* Search for keyLength */
            short keyLength = DEF_RSA_KEYLEN;
            try {
                short pos = UtilTLV.findTag(buf, offset_cdata, lc, (byte) 0x91);
                if(buf[++pos] != (byte) 0x02) { // Length: must be 2.
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
                keyLength = (short) ((buf[++pos] << 8) + buf[++pos]);
            } catch (NotFoundException e) {
                keyLength = DEF_RSA_KEYLEN;
            } catch (InvalidArgumentsException e) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }

            switch (keyLength) {
            case KeyBuilder.LENGTH_RSA_1024:
            case KeyBuilder.LENGTH_RSA_1536:
            case KeyBuilder.LENGTH_RSA_2048:
            case KeyBuilder_LENGTH_RSA_3072:
            case KeyBuilder.LENGTH_RSA_4096:
                break;
            default:
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }

            // Command chaining might be used for ECC, but not for RSA.
            if(isCommandChainingCLA(apdu)) {
                ISOException.throwIt(ISO7816.SW_COMMAND_CHAINING_NOT_SUPPORTED);
            }
            try {
                kp = new KeyPair(KeyPair.ALG_RSA_CRT, keyLength);
            } catch(CryptoException e) {
                if(e.getReason() == CryptoException.NO_SUCH_ALGORITHM) {
                    ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                }
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
            }
            kp.genKeyPair();
            if(keys[privKeyRef] != null) {
                keys[privKeyRef].clearKey();
            }
            keys[privKeyRef] = kp.getPrivate();
            if(JCSystem.isObjectDeletionSupported()) {
                JCSystem.requestObjectDeletion();
            }

            // Return pubkey. See ISO7816-8 table 3.
            sendRSAPublicKey(apdu, ((RSAPublicKey)(kp.getPublic())));

            break;

        case ALG_GEN_EC:
            if((p1 != (byte) 0x00) || p2 != (byte) 0x00) {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
            lc = doChainingOrExtAPDU(apdu);

            /* Search for prime */
            short pos = 0;
            try {
                pos = UtilTLV.findTag(ram_buf, (short) 0, lc, (byte) 0x81);
            } catch (NotFoundException e) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            } catch (InvalidArgumentsException e) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            pos++;
            short len = 0;
            try {
                len = UtilTLV.decodeLengthField(ram_buf, pos);
            } catch (InvalidArgumentsException e) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            // Try to calculate field length frome prime length.
            short field_len = getEcFpFieldLength(len);

            // Try to instantiate key objects of that length
            try {
                privKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, field_len, false);
                pubKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, field_len, false);
                kp = new KeyPair(pubKey, privKey);
            } catch(CryptoException e) {
                if(e.getReason() == CryptoException.NO_SUCH_ALGORITHM) {
                    ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                }
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
            }
            try {
                initEcParams(ram_buf, (short) 0, lc, pubKey);
                initEcParams(ram_buf, (short) 0, lc, privKey);
            } catch (NotFoundException e) {
                // Parts of the data needed to initialize the EC keys were missing.
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            } catch (InvalidArgumentsException e) {
                // Malformatted ASN.1.
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            try {
                kp.genKeyPair();
            } catch (CryptoException e) {
                if(e.getReason() == CryptoException.ILLEGAL_VALUE) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
            }
            if(keys[privKeyRef] != null) {
                keys[privKeyRef].clearKey();
            }
            keys[privKeyRef] = privKey;
            if(JCSystem.isObjectDeletionSupported()) {
                JCSystem.requestObjectDeletion();
            }

            Util.arrayFillNonAtomic(ram_buf, (short)0, ram_buf_size, (byte)0x00);
            ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] = 0;
            // Return pubkey. See ISO7816-8 table 3.
            try {
                sendECPublicKey(apdu, pubKey);
            } catch (InvalidArgumentsException e) {
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
            } catch (NotEnoughSpaceException e) {
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
            }
            break;

        default:
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    /**
     * \brief Encode a >= 1024 bit RSAPublicKey according to ISO7816-8 table 3 and send it as a response,
     * using an extended APDU.
     *
     * \see ISO7816-8 table 3.
     *
     * \param apdu The apdu to answer. setOutgoing() must not be called already.
     *
     * \param key The RSAPublicKey to send.
     * 			Can be null for the secound part if there is no support for extended apdus.
     */
    private void sendRSAPublicKey(APDU apdu, RSAPublicKey key) {
        short le = apdu.setOutgoing();
        short pos = 0;
        short keyLength = (short) (key.getSize() / 8);

        ram_buf[pos++] = (byte) 0x7F; // Interindustry template for nesting one set of public key data objects.
        ram_buf[pos++] = (byte) 0x49; // "
        ram_buf[pos++] = (byte) 0x82; // Length field: 3 Bytes.
        ram_buf[pos++] = (byte) ((short) (keyLength + 9) / 256); // Length + 9
        ram_buf[pos++] = (byte) ((short) (keyLength + 9) % 256); // "

        ram_buf[pos++] = (byte) 0x81; // RSA public key modulus tag.
        ram_buf[pos++] = (byte) 0x82; // Length field: 3 Bytes.
        ram_buf[pos++] = (byte) (keyLength / 256); // Length
        ram_buf[pos++] = (byte) (keyLength % 256); // "
        pos += key.getModulus(ram_buf, pos);
        ram_buf[pos++] = (byte) 0x82; // RSA public key exponent tag.
        ram_buf[pos++] = (byte) 0x03; // Length: 3 Bytes.
        pos += key.getExponent(ram_buf, pos);

        sendLargeData(apdu, (short)0, pos);
    }


    /**
     * \brief Process the GET RESPONSE APDU (INS = C0).
     *
     * If there is content available in ram_buf that could not be sent in the last operation,
     * the host should use this APDU to get the data. The data is cached in ram_buf.
     *
     * \param apdu The GET RESPONSE apdu.
     *
     * \throw ISOException SW_CONDITIONS_NOT_SATISFIED, SW_UNKNOWN, SW_CORRECT_LENGTH.
     */
    private void processGetResponse(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short le = apdu.setOutgoing();

        if( ! pin.isValidated() ) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if(ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING] <= (short) 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        short expectedLe = ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING] > 256 ?
                           256 : ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING];
        if(le != expectedLe) {
            ISOException.throwIt( (short)(ISO7816.SW_CORRECT_LENGTH_00 | expectedLe) );
        }

        sendLargeData(apdu, ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS],
                      ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING]);
    }

    /**
     * \brief Send the data from ram_buf, using either extended APDUs or GET RESPONSE.
     *
     * \param apdu The APDU object, in STATE_OUTGOING state.
     *
     * \param pos The position in ram_buf at where the data begins
     *
     * \param len The length of the data to be sent. If zero, 9000 will be
     *            returned
     */
    private void sendLargeData(APDU apdu, short pos, short len) {
        if(len <= 0) {
            ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING] = 0;
            ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] = 0;
            return;
        }

        if((short)(pos + len) > ram_buf_size) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }

        if(DEF_EXT_APDU) {
            apdu.setOutgoingLength(len);
            apdu.sendBytesLong(ram_buf, pos, len);
        } else {
            // We have 256 Bytes send-capacity per APDU.
            // Send directly from ram_buf, then prepare for chaining.
            short sendLen = len > 256 ? 256 : len;
            apdu.setOutgoingLength(sendLen);
            apdu.sendBytesLong(ram_buf, pos, sendLen);
            short bytesLeft = (short)(len - sendLen);
            if(bytesLeft > 0) {
                ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING] = bytesLeft;
                ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] = (short)(pos + sendLen);
                short getRespLen = bytesLeft > 256 ? 256 : bytesLeft;
                ISOException.throwIt( (short)(ISO7816.SW_BYTES_REMAINING_00 | getRespLen) );
                // The next part of the data is now in ram_buf, metadata is in ram_chaining_cache.
                // It can be fetched by the host via GET RESPONSE.
            } else {
                ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING] = 0;
                ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] = 0;
                return;
            }
        }
    }

    /**
     * \brief Encode a ECPublicKey according to ISO7816-8 table 3 and send it as a response,
     * using an extended APDU.
     *
     * \see ISO7816-8 table 3.
     *
     * \param The apdu to answer. setOutgoing() must not be called already.
     *
     * \throw InvalidArgumentsException Field length of the EC key provided can not be handled.
     *
     * \throw NotEnoughSpaceException ram_buf is too small to contain the EC key to send.
     */
    private void sendECPublicKey(APDU apdu, ECPublicKey key) throws InvalidArgumentsException, NotEnoughSpaceException {
        short pos = 0;
        final short field_bytes = (key.getSize()%8 == 0) ? (short)(key.getSize()/8) : (short)(key.getSize()/8+1);
        short len, r;

        // Return pubkey. See ISO7816-8 table 3.
        len = (short)(7 // We have: 7 tags,
                      + (key.getSize() >= LENGTH_EC_FP_512 ? 9 : 7) // 7 length fields, of which 2 are 2 byte fields when using 521 bit curves,
                      + 8 * field_bytes + 4); // 4 * field_len + 2 * 2 field_len + cofactor (2 bytes) + 2 * uncompressed tag
        pos += UtilTLV.writeTagAndLen((short)0x7F49, len, ram_buf, pos);

        // Prime - "P"
        len = field_bytes;
        pos += UtilTLV.writeTagAndLen((short)0x81, len, ram_buf, pos);
        r = key.getField(ram_buf, pos);
        if(r < len) {
            // If the parameter has fewer bytes than the field length, we fill
            // the MSB's with zeroes.
            Util.arrayCopyNonAtomic(ram_buf, pos, ram_buf, (short)(pos+len-r), r);
            Util.arrayFillNonAtomic(ram_buf, pos, (short)(len-r), (byte)0x00);
        } else if (r > len) {
            throw InvalidArgumentsException.getInstance();
        }
        pos += len;

        // First coefficient - "A"
        len = field_bytes;
        pos += UtilTLV.writeTagAndLen((short)0x82, len, ram_buf, pos);
        r = key.getA(ram_buf, pos);
        if(r < len) {
            Util.arrayCopyNonAtomic(ram_buf, pos, ram_buf, (short)(pos+len-r), r);
            Util.arrayFillNonAtomic(ram_buf, pos, (short)(len-r), (byte)0x00);
        } else if (r > len) {
            throw InvalidArgumentsException.getInstance();
        }
        pos += len;

        // Second coefficient - "B"
        len = field_bytes;
        pos += UtilTLV.writeTagAndLen((short)0x83, len, ram_buf, pos);
        r = key.getB(ram_buf, pos);
        if(r < len) {
            Util.arrayCopyNonAtomic(ram_buf, pos, ram_buf, (short)(pos+len-r), r);
            Util.arrayFillNonAtomic(ram_buf, pos, (short)(len-r), (byte)0x00);
        } else if (r > len) {
            throw InvalidArgumentsException.getInstance();
        }
        pos += len;

        // Generator - "PB"
        len = (short)(1 + 2 * field_bytes);
        pos += UtilTLV.writeTagAndLen((short)0x84, len, ram_buf, pos);
        r = key.getG(ram_buf, pos);
        if(r < len) {
            Util.arrayCopyNonAtomic(ram_buf, pos, ram_buf, (short)(pos+len-r), r);
            Util.arrayFillNonAtomic(ram_buf, pos, (short)(len-r), (byte)0x00);
        } else if (r > len) {
            throw InvalidArgumentsException.getInstance();
        }
        pos += len;

        // Order - "Q"
        len = field_bytes;
        pos += UtilTLV.writeTagAndLen((short)0x85, len, ram_buf, pos);
        r = key.getR(ram_buf, pos);
        if(r < len) {
            Util.arrayCopyNonAtomic(ram_buf, pos, ram_buf, (short)(pos+len-r), r);
            Util.arrayFillNonAtomic(ram_buf, pos, (short)(len-r), (byte)0x00);
        } else if (r > len) {
            throw InvalidArgumentsException.getInstance();
        }
        pos += len;

        // Public key - "PP"
        len = (short)(1 + 2 * field_bytes);
        pos += UtilTLV.writeTagAndLen((short)0x86, len, ram_buf, pos);
        r = key.getW(ram_buf, pos);
        if(r < len) {
            Util.arrayCopyNonAtomic(ram_buf, pos, ram_buf, (short)(pos+len-r), r);
            Util.arrayFillNonAtomic(ram_buf, pos, (short)(len-r), (byte)0x00);
        } else if (r > len) {
            throw InvalidArgumentsException.getInstance();
        }
        pos += len;

        // Cofactor
        len = 2;
        pos += UtilTLV.writeTagAndLen((short)0x87, len, ram_buf, pos);
        Util.setShort(ram_buf, pos, key.getK());
        pos += 2;

        // ram_buf now contains the complete public key.
        apdu.setOutgoing();
        sendLargeData(apdu, (short)0, pos);
    }

    /**
     * \brief Process the MANAGE SECURITY ENVIRONMENT apdu (INS = 22).
     *
     * \attention Only SET is supported. RESTORE will reset the security environment.
     *				The security environment will be cleared upon deselection of the applet.
     * 				STOREing and ERASEing of security environments is not supported.
     *
     * \param apdu The apdu.
     *
     * \throw ISOException SW_SECURITY_STATUS_NOT_SATISFIED, SW_WRONG_LENGTH, SW_DATA_INVALID,
     *						SW_INCORRECT_P1P2, SW_FUNC_NOT_SUPPORTED, SW_COMMAND_NOT_ALLOWED.
     */
    public void processManageSecurityEnvironment(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short lc;
        short pos = 0;
        short offset_cdata;
        byte algRef = 0;
        short privKeyRef = -1;

        // Check PIN
        if( ! pin.isValidated() ) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        // Bytes received must be Lc.
        lc = apdu.setIncomingAndReceive();
        if(lc != apdu.getIncomingLength()) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        offset_cdata = apdu.getOffsetCdata();

        // TLV structure consistency check.
        if( ! UtilTLV.isTLVconsistent(buf, offset_cdata, lc)) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        /* Extract data: */
        switch(p1) {
        case (byte) 0x41:
            // SET Computation, decipherment, internal authentication and key agreement.

            // Algorithm reference.
            try {
                pos = UtilTLV.findTag(buf, offset_cdata, (byte) lc, (byte) 0x80);
            } catch (NotFoundException e) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            } catch (InvalidArgumentsException e) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            if(buf[++pos] != (byte) 0x01) { // Length must be 1.
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            // Set the current algorithm reference.
            algRef = buf[++pos];

            // Private key reference (Index in keys[]-array).
            try {
                pos = UtilTLV.findTag(buf, offset_cdata, (byte) lc, (byte) 0x84);
            } catch (NotFoundException e) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            } catch (InvalidArgumentsException e) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            if(buf[++pos] != (byte) 0x01 // Length: must be 1 - only one key reference (byte) provided.
                    || buf[++pos] >= KEY_MAX_COUNT) { // Value: KEY_MAX_COUNT may not be exceeded. Valid key references are from 0..KEY_MAX_COUNT.
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            privKeyRef = buf[pos];
            break;

        case (byte) 0xF3:
            // RESTORE // Set sec env constants to default values.
            algRef = 0;
            privKeyRef = -1;
            break;

        case (byte) 0x81: // SET Verification, encipherment, external authentication and key agreement.
        case (byte) 0xF4: // ERASE
        case (byte) 0xF2: // STORE
        default:
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }

        /* Perform checks (Note: Nothing is updated yet) */
        switch(p2) {
        case (byte) 0x00:
            /* *****************
             * Key generation. *
             *******************/

            if(algRef != ALG_GEN_EC
                    && algRef != ALG_GEN_RSA) {
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }
            // Check: We need a private key reference.
            if(privKeyRef < 0) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            if(algRef == ALG_GEN_EC && ecdsaSignaturePrecomp == null) {
                // There are cards that do not support ECDSA at all.
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }
            break;

        case (byte) 0xB6:
            /* ***********
             * Signature *
             *************/

            // Check: We need a private key reference.
            if(privKeyRef == -1) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }

            // Supported signature algorithms: RSA with PKCS1 padding, ECDSA with raw input.
            if(algRef == ALG_RSA_PAD_PKCS1) {
                // Key reference must point to a RSA private key.
                if(keys[privKeyRef].getType() != KeyBuilder.TYPE_RSA_CRT_PRIVATE) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }

            } else if(algRef == ALG_ECDSA_PRECOMPUTED_HASH) {
                // Key reference must point to a EC private key.
                if(keys[privKeyRef].getType() != KeyBuilder.TYPE_EC_FP_PRIVATE) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
                if(ecdsaSignaturePrecomp == null) {
                    ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                }

            } else {
                // No known or supported signature algorithm.
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }
            break;

        case (byte) 0xB7:
            /* ************
             * Derive *
             **************/

            // For derivation, only ECDH is supported.
            if(algRef == ALG_ECDH) {
                // Check: We need a private key reference.
                if(privKeyRef == -1) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
                // Key reference must point to a EC private key.
                if(keys[privKeyRef].getType() != KeyBuilder.TYPE_EC_FP_PRIVATE) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
                if(ecdh == null) {
                    ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                }
            } else {
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }
            break;

        case (byte) 0xB8:
            /* ************
             * Decryption *
             **************/

            // For decryption, only RSA with PKCS1 padding is supported.
            if(algRef == ALG_RSA_PAD_PKCS1) {
                // Check: We need a private key reference.
                if(privKeyRef == -1) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
                // Key reference must point to a RSA private key.
                if(keys[privKeyRef].getType() != KeyBuilder.TYPE_RSA_CRT_PRIVATE) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
            } else {
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }
            break;

        default:
            /* Unsupported or unknown P2. */
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }

        // Finally, update the security environment.
        JCSystem.beginTransaction();
        currentAlgorithmRef[0] = algRef;
        currentPrivateKeyRef[0] = privKeyRef;
        JCSystem.commitTransaction();

    }

    /**
     * \brief Process the PERFORM SECURITY OPERATION apdu (INS = 2A).
     *
     * This operation is used for cryptographic operations
     * (Computation of digital signatures, decrypting.).
     *
     * \param apdu The PERFORM SECURITY OPERATION apdu.
     *
     * \throw ISOException SW_SECURITY_STATUS_NOT_SATISFIED, SW_INCORRECT_P1P2 and
     * 			the ones from computeDigitalSignature() and decipher().
     */
    private void processPerformSecurityOperation(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];

        if( ! pin.isValidated() ) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if(p1 == (byte) 0x9E && p2 == (byte) 0x9A) {
            computeDigitalSignature(apdu);
        } else if(p1 == (byte) 0x80 && p2 == (byte) 0x86) {
            decipher(apdu);
        } else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

    }

    /**
     * \brief Decipher (or ECDH derive) the data from the apdu using the private key referenced by
     * 			an earlier MANAGE SECURITY ENVIRONMENT apdu.
     *
     * \param apdu The PERFORM SECURITY OPERATION apdu with P1=80 and P2=86.
     *
     * \throw ISOException SW_CONDITIONS_NOT_SATISFIED, SW_WRONG_LENGTH and
     *						SW_WRONG_DATA
     */
    private void decipher(APDU apdu) {
        short offset_cdata;
        short lc;
        short decLen = -1;
        short derLen = -1;

        lc = doChainingOrExtAPDU(apdu);
        offset_cdata = 0;

        // Padding indicator should be "No further indication".
        if(ram_buf[offset_cdata] != (byte) 0x00) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        switch(currentAlgorithmRef[0]) {

        case ALG_RSA_PAD_PKCS1:
            // Get the key - it must be an RSA private key,
            // checks have been done in MANAGE SECURITY ENVIRONMENT.
            RSAPrivateCrtKey theKey = (RSAPrivateCrtKey) keys[currentPrivateKeyRef[0]];

            // Check the length of the cipher.
            // Note: The first byte of the data field is the padding indicator
            //		 and therefor not part of the ciphertext.
            if((short)(lc-1) !=  (short)(theKey.getSize() / 8)) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }

            rsaPkcs1Cipher.init(theKey, Cipher.MODE_DECRYPT);
            try {
                decLen = rsaPkcs1Cipher.doFinal(ram_buf, (short)(offset_cdata+1), (short)(lc-1),
                                                ram_buf, (short) 0);
            } catch(CryptoException e) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }

            // A single short APDU can handle only 256 bytes - we use sendLargeData instead
            apdu.setOutgoing();
            sendLargeData(apdu, (short)0, decLen);
            break;

        case ALG_ECDH:
            // Check if we support ECDH
            if (ecdh == null) {
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }

            // Get the key - it must be an ECC private key,
            // checks have been done in MANAGE SECURITY ENVIRONMENT.
            ECPrivateKey ecKey = (ECPrivateKey) keys[currentPrivateKeyRef[0]];

            // Perform ECDH
            // Note: The first byte of the data field is the padding indicator
            //		 and therefore not part of the data.
            ecdh.init(ecKey);
            derLen = ecdh.generateSecret(ram_buf, (short)(offset_cdata+1), (short)(lc-1),
                                         ram_buf, (short) 0);

            // A single short APDU can handle 256 bytes - only one send operation neccessary.
            short le = apdu.setOutgoing();
            if(le < derLen) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            apdu.setOutgoingLength(derLen);
            apdu.sendBytesLong(ram_buf, (short) 0, derLen);
            break;

        default:
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
    }

    /**
     * \brief Fit the data in the buffer to the length of the selected key size.
     * 			If data length is shorter then key length, data will be filled up with zeros in front of data
     * 			If data length is bigger then key length, the input data will will be truncated to the key lengths leftmost bytes
     *
     * \param keySize Key size in bits
     *
     * \param in Contains the data
     *
     * \param inOffset Offset in the buffer where the data begins
     *
     * \param inLen Length of the data in the buffer
     *
     * \param dataBuff Output buffer
     *
     * \return Number of bytes of signature output in dataBuff
     */
    private short fitDataToKeyLength(short keySize, byte[] in, short inOffset, short inLen, byte[] dataBuff) {
        keySize += 7;
        keySize /= 8;
        if (inLen < keySize) {
            Util.arrayFillNonAtomic(dataBuff, (short) 0, (short) (keySize - inLen), (byte) 0);
            Util.arrayCopyNonAtomic(in, inOffset, dataBuff, (short) (keySize - inLen), inLen);
        } else {
            Util.arrayCopyNonAtomic(in, inOffset, dataBuff, (short) 0, keySize);
        }
        return keySize;
    }

    /**
     * \brief Compute a digital signature of the data from the apdu
     * 			using the private key referenced by	an earlier
     *			MANAGE SECURITY ENVIRONMENT apdu.
     *
     * \attention The apdu should contain a hash, not raw data for RSA keys.
     * 				PKCS1 padding will be applied if neccessary.
     *
     * \param apdu The PERFORM SECURITY OPERATION apdu with P1=9E and P2=9A.
     *
     * \throw ISOException SW_CONDITIONS_NOT_SATISFIED, SW_WRONG_LENGTH
     * 						and SW_UNKNOWN.
     */
    private void computeDigitalSignature(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        short offset_cdata;
        short lc;
        short sigLen = 0;
        ECPrivateKey ecKey;
        short le;

        switch(currentAlgorithmRef[0]) {
        case ALG_RSA_PAD_PKCS1:
            // Receive.
            // Bytes received must be Lc.
            lc = apdu.setIncomingAndReceive();
            if(lc != apdu.getIncomingLength()) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            offset_cdata = apdu.getOffsetCdata();

            // RSA signature operation.
            RSAPrivateCrtKey rsaKey = (RSAPrivateCrtKey) keys[currentPrivateKeyRef[0]];
            short keyLength = (short) (keys[currentPrivateKeyRef[0]].getSize() / 8);

            if(lc > (short) (keyLength - 9)) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }

            rsaPkcs1Cipher.init(rsaKey, Cipher.MODE_ENCRYPT);
            sigLen = rsaPkcs1Cipher.doFinal(buf, offset_cdata, lc, ram_buf, (short)0);

            if(sigLen != keyLength) {
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
            }

            // A single short APDU can handle only 256 bytes - we use sendLargeData instead
            apdu.setOutgoing();
            sendLargeData(apdu, (short)0, sigLen);
            break;

         case ALG_ECDSA_PRECOMPUTED_HASH:
            // Check if supported
            if (ecdsaSignaturePrecomp == null) {
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }

            // Receive assuming that all input data fit inside 1 APDU
            // Bytes received must be Lc.
            lc = apdu.setIncomingAndReceive();
            if(lc != apdu.getIncomingLength()) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            offset_cdata = apdu.getOffsetCdata();

            // ECDSA signature operation.
            ecKey = (ECPrivateKey) keys[currentPrivateKeyRef[0]];

            // Not recommended (FIPS 186-4, 6.4)
            // if (lc < MessageDigest.LENGTH_SHA_256) {
            //     ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            // }

            // Sign data in one go
            ecdsaSignaturePrecomp.init(ecKey, Signature.MODE_SIGN);
            if (ecdsaSHA512) {
                short fittedLength = fitDataToKeyLength(ecKey.getSize() > 8*MessageDigest.LENGTH_SHA_512 ? 8*MessageDigest.LENGTH_SHA_512 : ecKey.getSize(), buf, offset_cdata, lc, ram_buf);
                sigLen = ecdsaSignaturePrecomp.signPreComputedHash(ram_buf, (short) 0, MessageDigest.LENGTH_SHA_512, ram_buf, (short) 0);
            } else {
                sigLen = ecdsaSignaturePrecomp.signPreComputedHash(buf, offset_cdata, lc, ram_buf, (short) 0);
            }

            // A single short APDU can handle 256 bytes - only one send operation neccessary.
            le = apdu.setOutgoing();
            if(le < sigLen) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            apdu.setOutgoingLength(sigLen);
            apdu.sendBytesLong(ram_buf, (short) 0, sigLen);
            break;

        default:
            // Wrong/unknown algorithm.
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    /**
     * \brief Process the GET DATA apdu (INS = CA).
     *
     * GET DATA is currently used for obtaining directory listing.
     *
     * \throw ISOException SW_INCORRECT_P1P2, SW_FILE_INVALID
     */
    private void processGetData(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];

        // Return directory entries
        if(p1 == 0x01 && p2 == 0) {
            fs.processGetData(apdu);
            return;
        }
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    /**
     * \brief Process the PUT DATA apdu (INS = DB).
     *
     * PUT DATA is currently used for private key import.
     *
     * \throw ISOException SW_SECURITY_STATUS_NOT_SATISFIED, SW_INCORRECT_P1P2
     */
    private void processPutData(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];

        if( ! pin.isValidated() ) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if(p1 == (byte) 0x3F && p2 == (byte) 0xFF) {
            if( ! private_key_import_allowed) {
                ISOException.throwIt(SW_COMMAND_NOT_ALLOWED_GENERAL);
            }
            importPrivateKey(apdu);
        } else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    /**
     * \brief Upload and import a usable private key.
     *
     * A preceeding MANAGE SECURITY ENVIRONMENT is necessary (like with key-generation).
     * The format of the data (of the apdu) must be BER-TLV,
     * Tag 7F48 ("T-L pair to indicate a private key data object") for RSA or tag 0xC1
     * for EC keys, containing the point Q.
     *
     * For RSA, the data to be submitted is quite large. It is required that command chaining is
     * used for the submission of the private key. One chunk of the chain (one apdu) must contain
     * exactly one tag (0x92 - 0x96). The first apdu of the chain must contain the outer tag (7F48).
     *
     * \throw ISOException SW_SECURITY_STATUS_NOT_SATISFIED, SW_DATA_INVALID, SW_WRONG_LENGTH.
     */
    private void importPrivateKey(APDU apdu) throws ISOException {
        short recvLen;
        short offset = 0;
        short len = 0;

        if( ! pin.isValidated() ) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        switch(currentAlgorithmRef[0]) {
        case ALG_GEN_RSA:
            // RSA key import.

            // This ensures that all the data is located in ram_buf, beginning at zero.
            recvLen = doChainingOrExtAPDU(apdu);

            // Parse the outer tag.
            if(ram_buf[offset] != (byte)0x7F || ram_buf[(short)(offset+1)] != (byte)0x48) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            offset += 2;
            try {
                len = UtilTLV.decodeLengthField(ram_buf, offset);
                offset += UtilTLV.getLengthFieldLength(len);
            } catch (InvalidArgumentsException e) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            if(len != (short)(recvLen - offset)) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            if( ! UtilTLV.isTLVconsistent(ram_buf, offset, len) )	{
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            // Import the key from the value field of the outer tag.
            try {
                importRSAkey(ram_buf, offset, len);
            } catch (InvalidArgumentsException e) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            } catch (NotFoundException e) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            break;

        case ALG_GEN_EC:
            // EC key import.

            // This ensures that all the data is located in ram_buf, beginning at zero.
            recvLen = doChainingOrExtAPDU(apdu);

            // Parse the outer tag.
            if( ram_buf[offset++] != (byte) 0xE0 ) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            try {
                len = UtilTLV.decodeLengthField(ram_buf, offset);
                offset += UtilTLV.getLengthFieldLength(len);
            } catch (InvalidArgumentsException e) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            if(len != (short)(recvLen - offset)) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            if( ! UtilTLV.isTLVconsistent(ram_buf, offset, len) )	{
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            // Import the key from the value field of the outer tag.
            try {
                importECkey(ram_buf, offset, len);
            } catch (InvalidArgumentsException e) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            } catch (NotFoundException e) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            break;
        default:
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    /**
     * \brief Receive the data sent by chaining or extended apdus and store it in ram_buf.
     *
     * This is a convienience method if large data has to be accumulated using command chaining
     * or extended apdus. The apdu must be in the INITIAL state, i.e. setIncomingAndReceive()
     * might not have been called already.
     *
     * \param apdu The apdu object in the initial state.
     *
     * \throw ISOException SW_WRONG_LENGTH
     */
    private short doChainingOrExtAPDU(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        short recvLen = apdu.setIncomingAndReceive();
        short offset_cdata = apdu.getOffsetCdata();

        // Receive data (short or extended).
        while (recvLen > 0) {
            if((short)(ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] + recvLen) > ram_buf_size) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            Util.arrayCopyNonAtomic(buf, offset_cdata, ram_buf, ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS], recvLen);
            ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] += recvLen;
            recvLen = apdu.receiveBytes(offset_cdata);
        }

        if(isCommandChainingCLA(apdu)) {
            // We are still in the middle of a chain, otherwise there would not have been a chaining CLA.
            // Make sure the caller does not forget to return as the data should only be interpreted
            // when the chain is completed (when using this method).
            ISOException.throwIt(ISO7816.SW_NO_ERROR);
            return (short)0;
        } else {
            // Chain has ended or no chaining.
            // We did receive the data, everything is fine.
            // Reset the current position in ram_buf.
            recvLen = (short) (recvLen + ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS]);
            ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] = 0;
            return recvLen;
        }
    }

    /**
     * \brief Update fields of the current private RSA key.
     *
     * A MANAGE SECURITY ENVIRONMENT must have preceeded, setting the current
     * algorithm reference to ALG_GEN_RSA.
     * This method creates a new instance of the current private key,
     * depending on the current algorithn reference.
     *
     * \param buf The buffer containing the information to update the private key
     *			field with. The format must be TLV-encoded with the tags:
     *				- 0x91: keyLength
     *				- 0x92: p
     *				- 0x93: q
     *				- 0x94: 1/q mod p
     *				- 0x95: d mod (p-1)
     *				- 0x96: d mod (q-1)
     *			Note: This buffer will be filled with 0x00 after the operation
     *			had been performed.
     *
     * \param bOff The offset at which the data in buf starts.
     *
     * \param bLen The length of the data in buf.
     *
     * \throw ISOException SW_CONDITION_NOT_SATISFIED   The current algorithm reference does not match.
     *                     SW_FUNC_NOT_SUPPORTED        Algorithm is unsupported by the card.
     *           		   SW_UNKNOWN                   Unknown error.
     *
     * \throw NotFoundException The buffer does not contain all the information needed to import a private key.
     *
     * \throw InvalidArgumentsException The buffer is malformatted.
     */
    private void importRSAkey(byte[] buf, short bOff, short bLen) throws ISOException, NotFoundException, InvalidArgumentsException {
        short pos = 0;
        short len;
        RSAPrivateCrtKey rsaPrKey = null;

        if(currentAlgorithmRef[0] != ALG_GEN_RSA) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        if( ! UtilTLV.isTLVconsistent(buf, bOff, bLen)) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        /* Get keyLength */
        short keyLength = DEF_RSA_KEYLEN;
        try {
            pos = UtilTLV.findTag(buf, bOff, bLen, (byte) 0x91);
            if(buf[++pos] != (byte) 0x02) { // Length: must be 2.
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            keyLength = (short) ((buf[++pos] << 8) + buf[++pos]);
        } catch (NotFoundException e) {
            keyLength = DEF_RSA_KEYLEN;
        } catch (InvalidArgumentsException e) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        switch (keyLength) {
        case KeyBuilder.LENGTH_RSA_1024:
        case KeyBuilder.LENGTH_RSA_1536:
        case KeyBuilder.LENGTH_RSA_2048:
        case KeyBuilder_LENGTH_RSA_3072:
        case KeyBuilder.LENGTH_RSA_4096:
            break;
        default:
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        try {
            rsaPrKey = (RSAPrivateCrtKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_CRT_PRIVATE, keyLength, false);
        } catch(CryptoException e) {
            if(e.getReason() == CryptoException.NO_SUCH_ALGORITHM) {
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
            return;
        }

        /* Set P */
        pos = UtilTLV.findTag(buf, bOff, bLen, (byte)0x92);
        pos++;
        len = UtilTLV.decodeLengthField(buf, pos);
        pos += UtilTLV.getLengthFieldLength(len);
        rsaPrKey.setP(buf, pos, len);

        /* Set Q */
        pos = UtilTLV.findTag(buf, bOff, bLen, (byte)0x93);
        pos++;
        len = UtilTLV.decodeLengthField(buf, pos);
        pos += UtilTLV.getLengthFieldLength(len);
        rsaPrKey.setQ(buf, pos, len);

        /* Set PQ (1/q mod p) */
        pos = UtilTLV.findTag(buf, bOff, bLen, (byte)0x94);
        pos++;
        len = UtilTLV.decodeLengthField(buf, pos);
        pos += UtilTLV.getLengthFieldLength(len);
        rsaPrKey.setPQ(buf, pos, len);

        /* Set DP1 (d mod (p-1)) */
        pos = UtilTLV.findTag(buf, bOff, bLen, (byte)0x95);
        pos++;
        len = UtilTLV.decodeLengthField(buf, pos);
        pos += UtilTLV.getLengthFieldLength(len);
        rsaPrKey.setDP1(buf, pos, len);

        /* Set DQ1 (d mod (q-1)) */
        pos = UtilTLV.findTag(buf, bOff, bLen, (byte)0x96);
        pos++;
        len = UtilTLV.decodeLengthField(buf, pos);
        pos += UtilTLV.getLengthFieldLength(len);
        rsaPrKey.setDQ1(buf, pos, len);

        if(rsaPrKey.isInitialized()) {
            // If the key is usable, it MUST NOT remain in buf.
            JCSystem.beginTransaction();
            Util.arrayFillNonAtomic(buf, bOff, bLen, (byte)0x00);
            if(keys[currentPrivateKeyRef[0]] != null) {
                keys[currentPrivateKeyRef[0]].clearKey();
            }
            keys[currentPrivateKeyRef[0]] = rsaPrKey;
            if(JCSystem.isObjectDeletionSupported()) {
                JCSystem.requestObjectDeletion();
            }
            JCSystem.commitTransaction();
        } else {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
    }

    /**
     * \brief Get the field length of an EC FP key using the amount of bytes
     * 			of a parameter (e.g. the prime).
     *
     * \return The bit length of the field.
     *
     * \throw ISOException SC_FUNC_NOT_SUPPORTED.
     */
    private short getEcFpFieldLength(short bytes) {
        switch(bytes) {
        case 24:
            return KeyBuilder.LENGTH_EC_FP_192;
        case 28:
            return LENGTH_EC_FP_224;
        case 32:
            return LENGTH_EC_FP_256;
        case 40:
            return LENGTH_EC_FP_320;
        case 48:
            return LENGTH_EC_FP_384;
        case 64:
            return LENGTH_EC_FP_512;
        case 66:
            return LENGTH_EC_FP_521;
        default:
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            return 0;
        }
    }

    /**
     * \brief Instatiate and initialize the current private (EC) key.
     *
     * A MANAGE SECURITY ENVIRONMENT must have preceeded, setting the current
     * algorithm reference to ALG_GEN_EC.
     * This method creates a new instance of the current private key.
     *
     * \param buf The buffer containing the private key. It must be a sequence of
     * 			the following TLV-encoded entries:
     * 				81 - prime
     * 				82 - coefficient A
     * 				83 - coefficient B
     * 				84 - base point G
     * 				85 - order
     * 				87 - cofactor
     * 				88 - private D
     * 			Note: This buffer will be filled with 0x00 after the operation had been performed.
     *
     * \param bOff The offset at which the data in buf starts.
     *
     * \param bLen The length of the data in buf.
     *
     * \throw ISOException SW_CONDITION_NOT_SATISFIED   The current algorithm reference does not match.
     *                     SW_FUNC_NOT_SUPPORTED        Algorithm is unsupported by the card.
     *           		   SW_UNKNOWN                   Unknown error.
     *
     * \throw NotFoundException The buffer does not contain all the information needed to import a private key.
     *
     * \throw InvalidArgumentsException The buffer is malformatted.
     */
    private void importECkey(byte[] buf, short bOff, short bLen) throws InvalidArgumentsException, NotFoundException, ISOException {
        short pos = 0;
        short len;
        short field_len;
        ECPrivateKey ecPrKey = null;

        if(currentAlgorithmRef[0] != ALG_GEN_EC) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        // Search for prime
        pos = UtilTLV.findTag(buf, bOff, bLen, (byte) 0x81);
        pos++;
        len = UtilTLV.decodeLengthField(buf, pos);
        // Try to calculate field length frome prime length.
        field_len = getEcFpFieldLength(len);

        // Try to instantiate key objects of that length
        try {
            ecPrKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, field_len, false);
        } catch(CryptoException e) {
            if(e.getReason() == CryptoException.NO_SUCH_ALGORITHM) {
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
            return;
        }
        initEcParams(buf, bOff, bLen, ecPrKey);

        // Set the private component "private D"
        pos = UtilTLV.findTag(buf, bOff, bLen, (byte)0x88);
        pos++;
        len = UtilTLV.decodeLengthField(buf, pos);
        pos += UtilTLV.getLengthFieldLength(len);
        ecPrKey.setS(buf, pos, len);

        if(ecPrKey.isInitialized()) {
            // If the key is usable, it MUST NOT remain in buf.
            JCSystem.beginTransaction();
            Util.arrayFillNonAtomic(buf, bOff, bLen, (byte)0x00);
            if(keys[currentPrivateKeyRef[0]] != null) {
                keys[currentPrivateKeyRef[0]].clearKey();
            }
            keys[currentPrivateKeyRef[0]] = ecPrKey;
            if(JCSystem.isObjectDeletionSupported()) {
                JCSystem.requestObjectDeletion();
            }
            JCSystem.commitTransaction();
        } else {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
    }

    /**
     * \brief Process the GET CHALLENGE instruction (INS = 84).
     *
     * The host may request a random number of length "Le". This random number
     * is currently _not_ used for any cryptographic function (e.g. secure
     * messaging) by the applet.
     *
     * \param apdu The GET CHALLENGE apdu with P1P2=0000.
     *
     * \throw ISOException SW_INCORRECT_P1P2, SW_WRONG_LENGTH, SW_FUNC_NOT_SUPPORTED.
     */
    private void processGetChallenge(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];

        if(randomData == null) {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }

        if(p1 != 0x00 || p1 != 0x00) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        short le = apdu.setOutgoing();
        if(le <= 0 || le > 256) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        randomData.generateData(buf, (short)0, le);
        apdu.setOutgoingLength(le);
        apdu.sendBytes((short)0, le);
    }

    /**
     * \brief Process the DELETE KEY instruction (INS = E5).
     *
     * Returns selected data
     *
     * \param apdu The DELETE_KEY apdu
     *
     * \throw ISOException ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, ISO7816.SW_DATA_INVALID.
     */
    private void processDeleteKey(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short offset_cdata;
        short lc;
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short privKeyRef = (short)p2;

        if( ! pin.isValidated() ) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if (p1 != 0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        if(privKeyRef < 0 || privKeyRef >= KEY_MAX_COUNT) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        if(keys[privKeyRef] == null) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        if(keys[privKeyRef].isInitialized()) {
            keys[privKeyRef].clearKey();
        }
        keys[privKeyRef] = null;
    }

    /**
     * \brief Process the INITIALISE_CARD instruction (INS = 51).
     * Returns nothing, optionally re-sets config parameters
     *
     * \param apdu The INITIALISE_CARD apdu with P1P2=0000.
     *
     * \throw ISOException SW_INCORRECT_P1P2.
     */
    private void processInitialiseCard(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short lc;

        if(p1 != 0x00 || p2 != 0x00) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        if( state == STATE_CREATION || sopin.isValidated() ) {
            // Check for new config
            lc = apdu.setIncomingAndReceive();
            if (lc > 0) {
                if(lc != apdu.getIncomingLength()) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                setDefaultValues(buf, apdu.getOffsetCdata(), (byte)lc, false);
            }
        }

        if( state != STATE_CREATION ) {
            return;
        }

        /**
         * Card fs may be in an invalid state due to aborted create_pkcs15 process
         */
        if (fs != null) {
            try {
                fs.clearContents();
            } catch (Exception e) {
            }
            fs = null;
        }
        if(JCSystem.isObjectDeletionSupported()) {
            JCSystem.requestObjectDeletion();
        }
        fs = new IsoFileSystem();
    }

    /**
     * \brief Process the ERASE_CARD instruction (INS = 50).
     * Returns nothing
     *
     * \param apdu The ERASE_CARD apdu with P1P2=0000.
     *
     * \throw ISOException SW_INCORRECT_P1P2.
     */
    private void processEraseCard(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];

        if(p1 != 0x00 || p2 != 0x00) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        // Require the SOPIN in STATE_OPERATIONAL_* and STATE_INITIALISATION.
        // STATE_TERMINATED and STATE_CREATION don't require SOPIN to be verified.
        if((state == STATE_OPERATIONAL_ACTIVATED
                    || state == STATE_OPERATIONAL_DEACTIVATED
                    || state == STATE_INITIALISATION)
                && !sopin.isValidated()) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        // Erase PIN, PUK & SO PIN (only if transport key was not set)
        pin = null;
        puk = null;
        if (transport_key == null)
            sopin = null;
        // Erase file system
        if (fs != null) {
            try {
                fs.clearContents();
            } catch (Exception e) {
            }
            fs = null;
        }
        // Clear keys
        for (short i = 0; i < KEY_MAX_COUNT; i++) {
            if(keys[i] != null) {
                keys[i].clearKey();
            }
            keys[i] = null;
        }
        // Set sec env constants to default values.
        currentAlgorithmRef[0] = 0;
        currentPrivateKeyRef[0] = -1;
        // Garbage collection...
        if(JCSystem.isObjectDeletionSupported()) {
            JCSystem.requestObjectDeletion();
        }
        state = STATE_CREATION;
        // Create new objects
        pin = new OwnerPIN(pin_max_tries, pin_max_length);
        puk = new OwnerPIN(PUK_MAX_TRIES, puk_length);
        puk_is_set = false;
        // If transport key was configured, then a valid SO PIN has to be presented during initialisation
        if (transport_key == null)
            sopin = new OwnerPIN(SOPIN_MAX_TRIES, sopin_length);
        fs = new IsoFileSystem();
    }

    /**
     * \brief Process the GET VALUE instruction (INS = 6C).
     *
     * Returns selected data
     *
     * \param apdu The GET VALUE apdu
     *
     * \throw ISOException SW_INCORRECT_P1P2, SW_WRONG_LENGTH.
     */
    private void processGetValue(APDU apdu) {
        // GET VALUE P1 parameters:
        final byte OPT_P1_SERIAL = (byte) 0x01;
        final byte OPT_P1_MEM = (byte) 0x02;
        final byte OPT_P1_INITCOUNTER = (byte) 0x03;

        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];

        if(p1 == OPT_P1_SERIAL && p2 == 0x00) {
            // Get serial
            short le = apdu.setOutgoing();
            if(le < serial.length) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            Util.arrayCopyNonAtomic(serial, (short)0, buf, (short)0, (short)serial.length);
            apdu.setOutgoingLength((short) serial.length);
            apdu.sendBytes((short) 0, (short) serial.length);
        } else if(p1 == OPT_P1_MEM) {
            // Get memory
            short le = apdu.setOutgoing();
            if(le < 4) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            JCSystem.getAvailableMemory(ram_chaining_cache, (short) 0, p2);
            buf[0] = (byte)(ram_chaining_cache[0] >> 8);
            buf[1] = (byte)(ram_chaining_cache[0] & 0xFF);
            buf[2] = (byte)(ram_chaining_cache[1] >> 8);
            buf[3] = (byte)(ram_chaining_cache[1] & 0xFF);
            apdu.setOutgoingLength((short) 4);
            apdu.sendBytes((short) 0, (short) 4);
        } else if(p1 == OPT_P1_INITCOUNTER && p2 == 0x00) {
            // Get memory
            short le = apdu.setOutgoing();
            if(le < 2) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            buf[0] = (byte)(initCounter >> 8);
            buf[1] = (byte)(initCounter & 0xFF);
            apdu.setOutgoingLength((short) 2);
            apdu.sendBytes((short) 0, (short) 2);
        } else
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

} // class IsoApplet
