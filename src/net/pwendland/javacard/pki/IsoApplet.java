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

package net.pwendland.javacard.pki;

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
import javacard.security.ECPublicKey;
import javacard.security.ECPrivateKey;
import javacardx.crypto.Cipher;
import javacardx.apdu.ExtendedLength;
import javacard.security.CryptoException;
import javacard.security.Signature;

/**
 * \brief The IsoApplet class.
 *
 * This applet has a filesystem and accepts relevent ISO 7816 instructions.
 * Access control is forced through a PIN and a PUK. The PUK is optional
 * (Set PUK_MUST_BE_SET). Security Operations are being processed directly in
 * this class. Only private keys are stored as Key-objects. Only security
 * operations with private keys can be performed (decrypt, sign with RSA,
 * sign with ECDSA).
 *
 * \author Philip Wendland
 */
public class IsoApplet extends Applet implements ExtendedLength {
    /* Card-specific configuration */
    public static final boolean DEF_EXT_APDU = false;

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
    // Status words:
    public static final short SW_PIN_TRIES_REMAINING = 0x63C0; // See ISO 7816-4 section 7.5.1

    /* PIN, PUK and key realted constants */
    // PIN:
    private static final byte PIN_MAX_TRIES = 3;
    private static final byte PIN_MIN_LENGTH = 4;
    private static final byte PIN_MAX_LENGTH = 16;
    // PUK:
    private static final boolean PUK_MUST_BE_SET = true;
    private static final byte PUK_MAX_TRIES = 5;
    private static final byte PUK_LENGTH = 16;
    // Keys:
    private static final short KEY_MAX_COUNT = 16;

    private static final byte ALG_GEN_RSA_2048 = (byte) 0xF3;
    private static final byte ALG_RSA_PAD_PKCS1 = (byte) 0x11;

    private static final byte ALG_GEN_EC_BRAINPOOLP192R1 = (byte) 0xE0;
    private static final byte ALG_GEN_EC_PRIME256V1 = (byte) 0xE1;
    private static final byte ALG_ECDSA_SHA1 = (byte) 0x21;

    /* Card/Applet lifecycle states */
    private static final byte STATE_CREATION = (byte) 0x00; // No restrictions, PUK not set yet.
    private static final byte STATE_INITIALISATION = (byte) 0x01; // PUK set, PIN not set yet. PUK may not be changed.
    private static final byte STATE_OPERATIONAL_ACTIVATED = (byte) 0x05; // PIN is set, data is secured.
    private static final byte STATE_OPERATIONAL_DEACTIVATED = (byte) 0x04; // Applet usage is deactivated. (Unused at the moment.)
    private static final byte STATE_TERMINATED = (byte) 0x0C; // Applet usage is terminated. (Unused at the moment.)

    /* Other constants */
    // "ram_buf" is used for:
    //		- Caching of the RSA 2048 bit public key for GET RESPONSE (in case of normal APDUs).
    //		- Caching of the ECC 256 bit public key information for GET RESPONSE (in case of normal APDUs).
    //		- Caching of data for DECIPHER for command chaining (in case of normal APDUs).
    private static final short RAM_BUF_SIZE = (short) 256;
    // "ram_chaining_cache" is used for:
    //		- Caching of the amount of bytes remainung.
    //		- Caching of the current send position.
    //		- Determining how many operations had previously been performed in the chain (re-use CURRENT_POS)
    private static final short RAM_CHAINING_CACHE_SIZE = (short) 2;
    private static final short RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING = (short) 0;
    private static final short RAM_CHAINING_CACHE_OFFSET_CURRENT_POS = (short) 1;

    /* Member variables: */
    private byte state;
    private IsoFileSystem fs = null;
    private OwnerPIN pin = null;
    private OwnerPIN puk = null;
    private byte[] currentAlgorithmRef = null;
    private short[] currentPrivateKeyRef = null;
    private Key[] keys = null;
    private byte[] ram_buf = null;
    private short[] ram_chaining_cache = null;
    private Cipher rsaPkcs1Cipher = null;
    private Signature ecdsaSignature = null;

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
        new IsoApplet();
    }

    /**
     * \brief Only this class's install method should create the applet object.
     */
    protected IsoApplet() {
        JCSystem.requestObjectDeletion(); // Check if the method is implemented by the JCVM.
        pin = new OwnerPIN(PIN_MAX_TRIES, PIN_MAX_LENGTH);
        puk = new OwnerPIN(PUK_MAX_TRIES, PUK_LENGTH);
        fs = new IsoFileSystem();
        ram_buf = JCSystem.makeTransientByteArray(RAM_BUF_SIZE, JCSystem.CLEAR_ON_DESELECT);
        ram_chaining_cache = JCSystem.makeTransientShortArray(RAM_CHAINING_CACHE_SIZE, JCSystem.CLEAR_ON_DESELECT);

        currentAlgorithmRef = JCSystem.makeTransientByteArray((short)1, JCSystem.CLEAR_ON_DESELECT);
        currentPrivateKeyRef = JCSystem.makeTransientShortArray((short)1, JCSystem.CLEAR_ON_DESELECT);
        keys = new Key[KEY_MAX_COUNT];

        rsaPkcs1Cipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
        ecdsaSignature = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);

        state = STATE_CREATION;
        register();
    }

    /**
     * \brief This method is called whenever the applet is being deselected.
     */
    public void deselect() {
        pin.reset();
        puk.reset();
        fs.setUserAuthenticated(false);
    }

    /**
     * \brief This method is called whenever the applet is being selected.
     */
    public boolean select() {
        if(state == STATE_CREATION
                || state == STATE_INITIALISATION) {
            fs.setUserAuthenticated(true);
        } else {
            fs.setUserAuthenticated(false);
        }
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
        byte cla = buffer[ISO7816.OFFSET_CLA];
        byte ins = buffer[ISO7816.OFFSET_INS];

        // Just return if we are being selected - command is destined for ISD
        // and no information has to be returned.
        if(selectingApplet()) {
            return;
        }

        // No secure messaging at the moment
        if(apdu.isSecureMessagingCLA()) {
            ISOException.throwIt(ISO7816.SW_SECURE_MESSAGING_NOT_SUPPORTED);
        }

        // Chaining only for PERFORM SECURITY OPERATION without extended APDUs.
        if( apdu.isCommandChainingCLA()
                && ( DEF_EXT_APDU
                     || ins != INS_PERFORM_SECURITY_OPERATION)
          ) {
            ISOException.throwIt(ISO7816.SW_COMMAND_CHAINING_NOT_SUPPORTED);
        }

        if(apdu.isISOInterindustryCLA()) {
            switch (ins) {
            case ISO7816.INS_SELECT:
                fs.processSelectFile(apdu);
                break;
            case INS_READ_BINARY:
                fs.processReadBinary(apdu);
                break;
            case INS_VERIFY:
                processVerify(apdu);
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
            case INS_CHANGE_REFERENCE_DATA:
                processChangeReferenceData(apdu);
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
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            } // switch
        } else {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
    }

    /**
     * \brief Process the VERIFY apdu (INS = 20).
     *
     * This apdu is used to verify a PIN and authenticate the user. A counter is used
     * to limit unsuccessful ties (i.e. brute force attacks).
     *
     * \param apdu The apdu.
     *
     * \throw ISOException SW_INCORRECT_P1P2, ISO7816.SW_WRONG_LENGTH, SW_PIN_TRIES_REMAINING.
     */
    private void processVerify(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        short offset_cdata;
        short lc;

        // P1P2 0001 only at the moment. (key-reference 01 = PIN)
        if(buf[ISO7816.OFFSET_P1] != 0x00 || buf[ISO7816.OFFSET_P2] != 0x01) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Bytes received must be Lc.
        lc = apdu.setIncomingAndReceive();
        if(lc != apdu.getIncomingLength()) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        offset_cdata = apdu.getOffsetCdata();

        // Lc might be 0, in this case the caller checks if verification is required.
        if((lc > 0 && (lc < PIN_MIN_LENGTH) || lc > PIN_MAX_LENGTH)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Pad the PIN if not done by caller, so no garbage from the APDU will be part of the PIN.
        Util.arrayFillNonAtomic(buf, (short)(offset_cdata + lc), (short)(PIN_MAX_LENGTH - lc), (byte) 0x00);

        // Check the PIN.
        if(!pin.check(buf, (short) offset_cdata, PIN_MAX_LENGTH)) {
            ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | pin.getTriesRemaining()));
            fs.setUserAuthenticated(false);
        } else {
            fs.setUserAuthenticated(true);
        }
    }

    /**
     * \brief Process the CHANGE REFERENCE DATA apdu (INS = 24).
     *
     * If the state is STATE_CREATION, we can set the PUK without verification.
     * The state will advance to STATE_INITIALISATION (i.e. the PUK must be set before the PIN).
     *
     * In a "later" state the user must authenticate himself to be able to change the PIN.
     *
     * \todo Allow setting the PIN in STATE_CREATION (to set up applet without PUK.), change to
     *			STATE_OPERATIONAL_ACTIVATED.
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
            // We _set_ the PUK or the PIN. If we set the PIN in this state, no PUK will be present on the card, ever.
            // Key reference must be 02 (PUK) or 01 (PIN). P1 must be 01 because no verification data should be present in this state.
            if(p1 != 0x01 || (p2 != 0x02 && p2 != 0x01) ) {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }

            if(p2 == 0x02) {
                // We set the PUK and advance to STATE_INITIALISATION.

                // Check length.
                if(lc != PUK_LENGTH) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }

                // Set PUK
                puk.update(buf, offset_cdata, (byte)lc);
                puk.resetAndUnblock();

                state = STATE_INITIALISATION;
            } else if(p2 == 0x01) {
                // We are supposed to set the PIN right away - no PUK will be set, ever.
                // This might me forbidden because of security policies:
                if(PUK_MUST_BE_SET) {
                    ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
                }

                // Check length.
                if(lc > PIN_MAX_LENGTH || lc < PIN_MIN_LENGTH) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                // Pad the PIN upon creation, so no garbage from the APDU will be part of the PIN.
                Util.arrayFillNonAtomic(buf, (short)(offset_cdata + lc), (short)(PIN_MAX_LENGTH - lc), (byte) 0x00);

                // Set PIN.
                pin.update(buf, offset_cdata, PIN_MAX_LENGTH);
                pin.resetAndUnblock();

                state = STATE_OPERATIONAL_ACTIVATED;
            }

        } else if(state == STATE_INITIALISATION) {
            // We _set_ the PIN (P2=01).
            if(buf[ISO7816.OFFSET_P1] != 0x01 || buf[ISO7816.OFFSET_P2] != 0x01) {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }

            // Check the PIN length.
            if(lc > PIN_MAX_LENGTH || lc < PIN_MIN_LENGTH) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }

            // Pad the PIN upon creation, so no garbage from the APDU will be part of the PIN.
            Util.arrayFillNonAtomic(buf, (short)(offset_cdata + lc), (short)(PIN_MAX_LENGTH - lc), (byte) 0x00);

            // Set PIN.
            pin.update(buf, offset_cdata, PIN_MAX_LENGTH);
            pin.resetAndUnblock();

            state = STATE_OPERATIONAL_ACTIVATED;
        } else {
            // We _change_ the PIN (P2=01).
            // P1 must be 00 as the old PIN must be provided, followed by new PIN without delimitation.
            // Both PINs must already padded (otherwise we can not tell when the old PIN ends.)
            if(buf[ISO7816.OFFSET_P1] != 0x00 || buf[ISO7816.OFFSET_P2] != 0x01) {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }

            // Check PIN lengths: PINs must be padded, i.e. Lc must be 2*PIN_MAX_LENGTH.
            if(lc != (short)(2*PIN_MAX_LENGTH)) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }

            // Check the old PIN.
            if(!pin.check(buf, offset_cdata, PIN_MAX_LENGTH)) {
                ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | pin.getTriesRemaining()));
            }

            // UPDATE PIN
            pin.update(buf, (short) (offset_cdata+PIN_MAX_LENGTH), PIN_MAX_LENGTH);

        }// end if(state == STATE_CREATION)
    }// end processChangeRefereceData()

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
        if(lc < (short)(PUK_LENGTH + PIN_MIN_LENGTH)
                || lc > (short)(PUK_LENGTH + PIN_MAX_LENGTH)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // We expect the PUK followed by a new PIN.
        if(p1 != (byte) 0x00 || p2 != (byte) 0x01) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Check the PUK.
        if(!puk.check(buf, offset_cdata, PUK_LENGTH)) {
            ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | puk.getTriesRemaining()));
        }

        // If we're here, the PUK was correct.
        // Pad the new PIN, if not done by caller. We don't want any gargabe from the APDU buffer to be part of the new PIN.
        Util.arrayFillNonAtomic(buf, (short)(offset_cdata + lc), (short)(PUK_LENGTH + PIN_MAX_LENGTH - lc), (byte) 0x00);

        // Set the PIN.
        pin.update(buf, (short)(offset_cdata+PUK_LENGTH), PIN_MAX_LENGTH);
        pin.resetAndUnblock();
    }

    /**
     * \brief Process the GENERATE ASYMMETRIC KEY PAIR apdu (INS = 46).
     *
     * Currently, only RSA 2048 bit keys are supported. A MANAGE SECURITY ENVIRONMENT must
     * have succeeded eralier to set parameters for key generation.
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
        KeyPair kp = null;
        ECPrivateKey privKey = null;
        ECPublicKey pubKey = null;

        if( ! pin.isValidated() ) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if(p1 != (byte) 0x42 || p2 != (byte) 0x00) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Lc should be 0.
        if(apdu.setIncomingAndReceive() != 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        switch(currentAlgorithmRef[0]) {
        case ALG_GEN_RSA_2048:
            if(ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING] > (short) 0) {
                // This is the second command of the chain - the keypair has already been generated.
                sendRSAPublicKey(apdu, null);
            } else {
                try {
                    kp = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_2048);
                } catch(CryptoException e) {
                    if(e.getReason() == CryptoException.NO_SUCH_ALGORITHM) {
                        ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                    }
                    ISOException.throwIt(ISO7816.SW_UNKNOWN);
                }
                kp.genKeyPair();
                keys[privKeyRef] = kp.getPrivate();

                // Return pubkey. See ISO7816-8 table 3.
                sendRSAPublicKey(apdu, ((RSAPublicKey)(kp.getPublic())));
            }
            break;

        case ALG_GEN_EC_BRAINPOOLP192R1:
            privKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_192, false);
            pubKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_192, false);
            kp = new KeyPair(pubKey, privKey);
            pubKey.setFieldFP(ECCurves.EC_BRAINPOOLP192R1_PARAM_P, (short) 0, (short) ECCurves.EC_BRAINPOOLP192R1_PARAM_P.length); // "p"
            pubKey.setA(ECCurves.EC_BRAINPOOLP192R1_PARAM_A, (short) 0, (short) ECCurves.EC_BRAINPOOLP192R1_PARAM_A.length);
            pubKey.setB(ECCurves.EC_BRAINPOOLP192R1_PARAM_B, (short) 0, (short) ECCurves.EC_BRAINPOOLP192R1_PARAM_B.length);
            pubKey.setG(ECCurves.EC_BRAINPOOLP192R1_PARAM_G, (short) 0, (short) ECCurves.EC_BRAINPOOLP192R1_PARAM_G.length); // G(x,y)
            pubKey.setR(ECCurves.EC_BRAINPOOLP192R1_PARAM_R, (short) 0, (short) ECCurves.EC_BRAINPOOLP192R1_PARAM_R.length); // Order of G - "q"
            pubKey.setK(ECCurves.EC_BRAINPOOLP192R1_PARAM_K); // Cofactor - "h"

            kp.genKeyPair();
            keys[privKeyRef] = kp.getPrivate();

            // Return pubkey. See ISO7816-8 table 3.
            sendECPublicKey(apdu, ((ECPublicKey)(kp.getPublic())));
            break;


        case ALG_GEN_EC_PRIME256V1:
            privKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, ECCurves.LENGTH_EC_FP_256, false);
            pubKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, ECCurves.LENGTH_EC_FP_256, false);
            kp = new KeyPair(pubKey, privKey);

            pubKey.setFieldFP(ECCurves.EC_PRIME256V1_PARAM_P, (short) 0, (short) ECCurves.EC_PRIME256V1_PARAM_P.length); // "p"
            pubKey.setA(ECCurves.EC_PRIME256V1_PARAM_A, (short) 0, (short) ECCurves.EC_PRIME256V1_PARAM_A.length);
            pubKey.setB(ECCurves.EC_PRIME256V1_PARAM_B, (short) 0, (short) ECCurves.EC_PRIME256V1_PARAM_B.length);
            pubKey.setG(ECCurves.EC_PRIME256V1_PARAM_G, (short) 0, (short) ECCurves.EC_PRIME256V1_PARAM_G.length); // G(x,y)
            pubKey.setR(ECCurves.EC_PRIME256V1_PARAM_R, (short) 0, (short) ECCurves.EC_PRIME256V1_PARAM_R.length); // Order of G - "q"
            pubKey.setK(ECCurves.EC_PRIME256V1_PARAM_K); // Cofactor - "h"

            kp.genKeyPair();
            keys[privKeyRef] = kp.getPrivate();

            // Return pubkey. See ISO7816-8 table 3.
            sendECPublicKey(apdu, ((ECPublicKey)(kp.getPublic())));
            break;

        default:
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    /**
     * \brief Encode a RSAPublicKey according to ISO7816-8 table 3 and send it as a response,
     * using an extended APDU.
     *
     * \see ISO7816-8 table 3.
     *
     * \param The apdu to answer. setOutgoing() must not be called already.
     */
    private void sendRSAPublicKey(APDU apdu, RSAPublicKey key) {
        byte[] buf = apdu.getBuffer();
        short le = apdu.setOutgoing();

        if(DEF_EXT_APDU) {
            if(le != 270) {
                apdu.setOutgoingLength((short) 270);
            }
            buf[(short) 0] = (byte) 0x7F; // Interindustry template for nesting one set of public key data objects.
            buf[(short) 1] = (byte) 0x49; // "
            buf[(short) 2] = (byte) 0x82; // Length field: 3 Bytes.
            buf[(short) 3] = (byte) 0x01; // Length : 265 Bytes.
            buf[(short) 4] = (byte) 0x09; // "

            buf[(short) 5] = (byte) 0x81; // RSA public key modulus tag.
            buf[(short) 6] = (byte) 0x82; // Length field: 3 Bytes.
            buf[(short) 7] = (byte) 0x01; // Length: 256 bytes.
            buf[(short) 8] = (byte) 0x00; // "

            // We can use a extended APDU.
            apdu.sendBytes((short) 0, (short) 9); // Early send, because the modulus will be big.
            if(key.getModulus(buf, (short) 0) != 256) { // Write the modulus to the apdu buffer.
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
            }
            apdu.sendBytes((short) 0, (short) 256); // Send the modulus.

            buf[(short) 0] = (byte) 0x82; // RSA public key exponent tag.
            buf[(short) 1] = (byte) 0x03; // Length: 3 Bytes.
            key.getExponent(buf, (short) 2);
            apdu.sendBytes((short) 0, (short) 5);

        } else {
            // We have 256 Bytes send-capacity per APDU.

            if(ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING] > (short) 0) {
                // Should not happen - there is old content to get with GET RESPONSE
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
            // We excpect Le to be 00.
            if(le != 256) {
                ISOException.throwIt(ISO7816.SW_CORRECT_LENGTH_00);
            }

            buf[(short) 0] = (byte) 0x7F; // Interindustry template for nesting one set of public key data objects.
            buf[(short) 1] = (byte) 0x49; // "
            buf[(short) 2] = (byte) 0x82; // Length field: 3 Bytes.
            buf[(short) 3] = (byte) 0x01; // Length : 265 Bytes.
            buf[(short) 4] = (byte) 0x09; // "

            buf[(short) 5] = (byte) 0x81; // RSA public key modulus tag.
            buf[(short) 6] = (byte) 0x82; // Length field: 3 Bytes.
            buf[(short) 7] = (byte) 0x01; // Length: 256 bytes.
            buf[(short) 8] = (byte) 0x00; // "
            // Currently there are 9 Bytes in the apdu buffer. The length of the modulus is 256 bytes - it does not fit in.
            // We have to split the modulus and send a part of it with the first apdu.
            // We write it to "ram_buf" first.
            if(key.getModulus(ram_buf, (short) 0) != 256) { // Write the modulus to the apdu buffer.
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
            }

            // Write the first part to the apdu buffer and send it.
            Util.arrayCopyNonAtomic(ram_buf, (short) 0, buf, (short) 9, (short) 247);
            apdu.setOutgoingLength((short) 256);
            apdu.sendBytes((short) 0, (short) 256);
            // Prepare ram_buf for the next send operation in the chain.
            short i;
            for(i = 0; i < 9 ; i++) {
                ram_buf[i] = ram_buf[(short)((short)247+i)];
            }
            ram_buf[(short) 9] = (byte) 0x82; // RSA public key exponent tag.
            ram_buf[(short) 10] = (byte) 0x03; // Length: 3 Bytes.
            key.getExponent(ram_buf, (short) 11);
            ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING] = (short) 14;
            ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] = (short) 0;
            ISOException.throwIt((short) (ISO7816.SW_BYTES_REMAINING_00
                                          | (short)((short)0x00FF & ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING]) )
                                );
            // The second part of the data is now in ram_buf, metadata is in ram_chaining_cache.
            // It can be fetched by the host via GET RESPONSE.
        }
    }


    /**
     * \brief Process the GET RESPONSE APDU (INS=C0).
     *
     * If there is content available in ram_buf that could not be sent in the last operation,
     * the host should use this APDU to get the data. The data is cached in ram_buf, i.e. only
     * one GET RESPONSE can be done with max. 256 bytes.
     *
     * \param apdu The GET RESPONSE apdu.
     *
     * \throw ISOException SW_CONDITIONS_NOT_SATISFIED, SW_UNKNOWN, SW_CORRECT_LENGTH.
     */
    private void processGetResponse(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short le = apdu.setOutgoing();

        if(ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING] <= (short) 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        if(ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING] > (short) 256) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }

        if(ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING] != le) {
            ISOException.throwIt((short)(ISO7816.SW_CORRECT_LENGTH_00
                                         | (short)((short)0x00FF & ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING])));
        }

        Util.arrayCopyNonAtomic(ram_buf, ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS],
                                buf, (short) 0, ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING]);
        apdu.setOutgoingLength(ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING]);
        apdu.sendBytes((short) 0, ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING]);

        ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING] = (short) 0;
        ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] = (short) 0;
        Util.arrayFillNonAtomic(ram_buf, (short) 0, RAM_BUF_SIZE, (byte) 0x00);
    }

    /**
     * \brief Encode a ECPublicKey according to ISO7816-8 table 3 and send it as a response,
     * using an extended APDU.
     *
     * \attention Only extended APDUs are supported at the moment for larger field sizes.
     *
     * \todo Add support for command chaining in addition to extended APDUs (DEF_EXT_APDU=false)
     *
     * \see ISO7816-8 table 3.
     *
     * \param The apdu to answer. setOutgoing() must not be called already.
     */
    private void sendECPublicKey(APDU apdu, ECPublicKey key) {
        byte[] buf = apdu.getBuffer();
        short le = apdu.setOutgoing();
        short pos = 0;
        short lengthPos = 0;

        // Return pubkey. See ISO7816-8 table 3.
        buf[pos++] = (byte) 0x7F;
        buf[pos++] = (byte) 0x49;
        if(key.getSize() == KeyBuilder.LENGTH_EC_FP_192) {
            buf[pos++] = (byte) 0x81; // Length field: 2 bytes.
            buf[pos++] = (byte) 0xD0; // Length will be 218 bytes.
        } else if(key.getSize() == ECCurves.LENGTH_EC_FP_256) {
            buf[pos++] = (byte) 0x82; // Length field: 3 bytes.
            buf[pos++] = (byte) 0x01; // Length will be 282 bytes.
            buf[pos++] = (byte) 0x1A;
        }

        // Prime - "P"
        buf[pos++] = (byte) 0x81; // Tag
        lengthPos = pos++; // Write the length later - we don't know it now.
        buf[lengthPos] = (byte) key.getField(buf, pos); // Length + Value
        pos += buf[lengthPos];

        // First coefficient - "A"
        buf[pos++] = (byte) 0x82;
        lengthPos = pos++;
        buf[lengthPos] = (byte) key.getA(buf, pos);
        pos += buf[lengthPos];

        // Second coefficient - "B"
        buf[pos++] = (byte) 0x83;
        lengthPos = pos++;
        buf[lengthPos] = (byte) key.getB(buf, pos);
        pos += buf[lengthPos];

        // Generator - "PB"
        buf[pos++] = (byte) 0x84;
        lengthPos = pos; // Don't incement pos - ISO doesn't want the "uncompressed" identifier (04).
        buf[lengthPos] = (byte) key.getG(buf, pos);
        pos += buf[lengthPos];
        buf[lengthPos]--;

        // Order - "Q"
        buf[pos++] = (byte) 0x85;
        lengthPos = pos++;
        buf[lengthPos]  = (byte) key.getR(buf, pos);
        pos += buf[lengthPos];

        // Cofactor
        buf[pos++] = (byte) 0x87;
        buf[pos++] = (byte) 0x02;
        Util.setShort(buf, pos, key.getK());
        pos+=2;

        if((key.getSize() == ECCurves.LENGTH_EC_FP_256 && DEF_EXT_APDU)
                || key.getSize() == KeyBuilder.LENGTH_EC_FP_192) {
            // Data fits in a extended or short APDU.
            // Public key - "PP"
            buf[pos++] = (byte) 0x86;
            lengthPos = pos; // Don't incement pos - ISO doesn't want the "uncompressed" identifier (04).
            buf[lengthPos] = (byte) key.getW(buf, pos);
            pos += buf[lengthPos];
            buf[lengthPos]--;
            apdu.setOutgoingLength(pos);
            apdu.sendBytes((short) 0, pos);
        } else {
            // No extended APDUs and 256 Bit field length - we have 284 bytes to send.
            // Send the W public point with the second APDU.
            // Send the first part, prepare ram_buf and make the caller use GET RESPONSE.

            if(ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING] > (short) 0) {
                // Should not happen - there is old content to get with GET RESPONSE
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }

            apdu.setOutgoingLength(pos);
            apdu.sendBytes((short) 0, pos);

            pos = (short) 0;
            ram_buf[pos++] = (byte) 0x86;
            lengthPos = pos; // Don't incement pos - ISO doesn't want the "uncompressed" identifier (04).
            ram_buf[lengthPos] = (byte) key.getW(ram_buf, pos);
            pos += ram_buf[lengthPos];
            ram_buf[lengthPos]--;

            ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING] = pos;
            ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] = (short) 0;
            ISOException.throwIt((short) (ISO7816.SW_BYTES_REMAINING_00
                                          | (short)((short)0x00FF & ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING]) )
                                );
            // The second part of the data is now in ram_buf, metadata is in ram_chaining_cache.
            // It can be fetched by the host via GET RESPONSE.
        }

    }

    /**
     * \brief Process the MANAGE SECURITY ENVIRONMENT apdu (INS = 22).
     *
     * \todo Add support for other algoritm references.
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
        short pos;
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
            pos = UtilTLV.findTag(buf, (short) offset_cdata, (byte) lc, (byte) 0x80);
            if(pos >= 0) {
                if(buf[++pos] != (byte) 0x01) { // Length must be 1.
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
                // Set the current algorithm reference.
                algRef = buf[++pos];
            } else {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }

            // Private key reference (Index in keys[]-array).
            pos = UtilTLV.findTag(buf, (short) offset_cdata, (byte) lc, (byte) 0x84);
            if(pos >= 0) {
                if(buf[++pos] != (byte) 0x01 // Length: must be 1 - only one key reference (byte) provided.
                        || buf[++pos] >= KEY_MAX_COUNT) { // Value: KEY_MAX_COUNT may not be exceeded. Valid key references are from 0..KEY_MAX_COUNT.
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
                privKeyRef = (short) buf[pos];
            } else { // No key reference given.
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
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

            if(algRef != ALG_GEN_EC_BRAINPOOLP192R1
                    && algRef != ALG_GEN_RSA_2048
                    && algRef != ALG_GEN_EC_PRIME256V1) {
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }
            // Check: We need a private key reference.
            if(privKeyRef < 0) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
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

            } else if(algRef == ALG_ECDSA_SHA1) {
                // Key reference must point to a EC private key.
                if(keys[privKeyRef].getType() != KeyBuilder.TYPE_EC_FP_PRIVATE) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }

            } else {
                // No known or supported signature algorithm.
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
     * \brief Process the PERFORM SECURITY OPERATION apdu (INS=2A).
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
     * \brief Decipher the data from the apdu using the private key referenced by
     * 			an earlier MANAGE SECURITY ENVIRONMENT apdu.
     *
     * \param apdu The PERFORM SECURITY OPERATION apdu with P1=80 and P2=86.
     *
     * \throw ISOException SW_CONDITIONS_NOT_SATISFIED, SW_WRONG_LENGTH and
     *						SW_WRONG_DATA
     */
    private void decipher(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte algoritm = (byte) (currentPrivateKeyRef[0] & 0x0F);
        short offset_cdata;
        short lc;
        short le;
        short decLen = -1;

        // Receive - only as much as the apdu buffer can hold.
        // Sould be enough for 2048 bit modulus blocks with extended APDUs.
        lc = apdu.setIncomingAndReceive();
        if(lc != apdu.getIncomingLength()) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        offset_cdata = apdu.getOffsetCdata();

        // Padding indicator should be "No further indication".
        if(DEF_EXT_APDU &&	buf[offset_cdata] != (byte) 0x00
                || !DEF_EXT_APDU && apdu.isCommandChainingCLA() && buf[offset_cdata] != (byte) 0x00
          ) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        // Use chaining if the card does not support extended APDUs.
        if( !DEF_EXT_APDU ) {
            if(apdu.isCommandChainingCLA()) {
                // Copy the first part of the block to ram_buf, except padding indicator byte.
                Util.arrayCopy(buf, (short)(apdu.getOffsetCdata()+1), ram_buf, (short) 0, (short)(lc-1));
                ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] = (short)(lc-1);
                ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING] = (short) 2;
                return;
            } else {
                Util.arrayCopy(buf, apdu.getOffsetCdata(),
                               ram_buf, ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS],
                               ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING]);
                ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] = (short) 256;
                ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING] = (short) 0;
            }
        }

        switch(currentAlgorithmRef[0]) {

        case ALG_RSA_PAD_PKCS1:
            // Get the key - it must be an RSA private key,
            // checks have been done in MANAGE SECURITY ENVIRONMENT.
            RSAPrivateCrtKey theKey = (RSAPrivateCrtKey) keys[currentPrivateKeyRef[0]];

            // Check the length of the cipher.
            // Note: The first byte of the data field is the padding indicator
            //		 and therefor not part of the ciphertext.
            if(
                DEF_EXT_APDU && (short)(lc-1) !=  (short)(theKey.getSize() / 8)
                || !DEF_EXT_APDU && ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] != (short)(theKey.getSize() / 8)
            ) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }

            rsaPkcs1Cipher.init(theKey, Cipher.MODE_DECRYPT);
            try {
                if( DEF_EXT_APDU ) {
                    decLen = rsaPkcs1Cipher.doFinal(buf, (short)(offset_cdata+1), (short)(lc-1),
                                                    buf, (short) 0);
                } else {
                    decLen = rsaPkcs1Cipher.doFinal(ram_buf, (short) 0, ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS],
                                                    buf, (short) 0);
                }
            } catch(CryptoException e) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }

            // We have to send at most 256 bytes. A short APDU can handle that - only one send operation neccessary.
            apdu.setOutgoingAndSend((short) 0, decLen);
            break;

        default:
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
    }

    /**
     * \brief Compute a digital signature of the data from the apdu
     * 			using the private key referenced by	an earlier
     *			MANAGE SECURITY ENVIRONMENT apdu.
     *
     * \todo XXX Is the maximum assumed data size of the apdu data correct? A hash for RSA
     *			will surely fit in, but for ECDSA?
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
        short le;
        short sigLen = 0;

        // Receive.
        // Bytes received must be Lc.
        lc = apdu.setIncomingAndReceive();
        if(lc != apdu.getIncomingLength()) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        offset_cdata = apdu.getOffsetCdata();

        switch(currentAlgorithmRef[0]) {
        case ALG_RSA_PAD_PKCS1:
            // RSA signature operation.
            RSAPrivateCrtKey rsaKey = (RSAPrivateCrtKey) keys[currentPrivateKeyRef[0]];

            if(lc > (short) 247) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }

            rsaPkcs1Cipher.init(rsaKey, Cipher.MODE_ENCRYPT);
            sigLen = rsaPkcs1Cipher.doFinal(buf, offset_cdata, lc, buf, (short)0);

            // Should not happen - RSA output is 256 Bytes. But better safe than sorry ;-)
            if(sigLen > buf.length) {
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
            }

            // A single short APDU can handle 256 bytes - only one send operation neccessary.
            apdu.setOutgoingAndSend((short) 0, sigLen);
            break;

        case ALG_ECDSA_SHA1:
            // Get the key - it must be a EC private key,
            // checks have been done in MANAGE SECURITY ENVIRONMENT.
            ECPrivateKey ecKey = (ECPrivateKey) keys[currentPrivateKeyRef[0]];

            final short blocksize = (short) (ecKey.getSize() / (short) 4);
            short length = lc;
            short pos = offset_cdata;

            // Initialisation should be done when:
            // 	- No command chaining is performed at all.
            //	- Command chaining is performed and this is the first apdu in the chain.
            if(ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] == (short) 0) {
                ecdsaSignature.init(ecKey, Signature.MODE_SIGN);
                if(apdu.isCommandChainingCLA()) {
                    ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] = (short) 1;
                }
            }

            while(length > 0) {
                if(length > blocksize) {
                    ecdsaSignature.update(buf, pos, blocksize);
                    pos += blocksize;
                    length -= blocksize;
                } else {
                    ecdsaSignature.update(buf, pos, length);
                    pos += length;
                    length = 0;
                }
            }

            if(!apdu.isCommandChainingCLA()) {
                sigLen = ecdsaSignature.sign(buf, pos, length, buf, (short) 0);
                ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] = (short) 0;
                apdu.setOutgoingAndSend((short) 0, sigLen);
            } else {
                ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS]++;
            }

            break;

        default:
            // Wrong/unknown algorithm.
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

} // class IsoApplet
