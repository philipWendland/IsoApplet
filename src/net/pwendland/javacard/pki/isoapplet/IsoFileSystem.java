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

import javacard.framework.*;

import net.pwendland.javacard.pki.isoapplet.UtilTLV;

/**
 * \brief The ISO 7816 compliant IsoFileSystem class.
 *
 * It is the root of the file structure and is therefor equivalent to the ISO Master File (MF).
 * Normally, most of the file system oriented operations should happen through one object of this class.
 *
 * Due to the ISO 7816-4 DF and EF selection (see section 7.1) the currently selected DF and EF
 * are being saved internally. File related operations are being executed upon those selected files respectively.
 * It is therefor possible to select a file and execute a number of operations upon this file without the need to
 * specify a target in each individual method call. This also saves execution time and reduces stack usage.
 *
 * \author Philip Wendland
 */
public class IsoFileSystem extends DedicatedFile {
    /* Additional ISO Status Words */
    public static final short SW_COMMAND_INCOMPATIBLE_WITH_FILE_STRUCTURE = 0x6981;
    public static final short SW_OFFSET_OUTSIDE_EF = 0x6B00;

    public static final byte OFFSET_CURRENT_DF = 0;
    public static final byte OFFSET_CURRENT_EF = 1;

    private Object[] currentlySelectedFiles = null;
    short currentRecordNum;
    private boolean[] isUserAuthenticated = null;


    /**
     * \brief Instantiate a new ISO 7816 compliant IsoFileSystem.
     *
     * The IsoFileSystem class should normally only be instanciated once. It represents the file system and
     * is therefor equivalemt to the ISO Master File (MF).
     * Most of the file system related operations are performed through the returned object.
     *
     * \see IsoFileSystem.
     *
     * \param fileID The file ID of the master file. Should be 0x3F00 as specified by ISO.
     *
     * \param fileControlInformation The FCI according to ISO 7816-4 table 12. Necessary tags: 82, 83. No copy is made.
     */
    public IsoFileSystem(short fileID, byte[] fileControlInformation) {
        super(fileID, fileControlInformation);
        this.currentRecordNum = 0;
        this.isUserAuthenticated = JCSystem.makeTransientBooleanArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
        this.currentlySelectedFiles = JCSystem.makeTransientObjectArray((short) 2, JCSystem.CLEAR_ON_DESELECT);
        this.currentlySelectedFiles[OFFSET_CURRENT_DF] = this;
    }


    /**
     * \brief Instantiate a new ISO 7816 compliant IsoFileSystem with a typical MF (FID 0x3F00, not shareable).
     *
     * \see IsoFileSystem(short fileID, byte[] fileControlInformation)
     */
    public IsoFileSystem() {
        this((short) 0x3F00, new byte[]	{(byte)0x6F, (byte)0x07, // FCI, Length 7.
                                         (byte)0x82, (byte)0x01, (byte)0x38, // File descriptor byte.
                                         (byte)0x83, (byte)0x02, (byte)0x3F, (byte)0x00
                                        }); // File ID.
    }

    /**
     * \brief Get the currently selected DF.
     *
     * \return The currently selected DF.
     */
    public DedicatedFile getCurrentlySelectedDF() {
        return ((DedicatedFile)currentlySelectedFiles[OFFSET_CURRENT_DF]);
    }

    /**
     * \brief Set the currently selected DF.
     *
     * \param fileID The ID of the file.
     *
     * \throw FileNotFoundException If the specified file was not found or was of the wrong type.
     */
    public void setCurrentlySelectedDF(short fileID) throws FileNotFoundException {
        selectFile( findFile(fileID, SPECIFY_DF) );
        return;
    }

    /**
     * \brief Get the currently selected Elementary File.
     *
     * \return The currently selected EF.
     */
    public ElementaryFile getCurrentlySelectedEF() {
        return ((ElementaryFile)currentlySelectedFiles[OFFSET_CURRENT_EF]);
    }

    /**
     * \brief Set the currently selected Elementary File.
     *
     * \brief fileID The ID of the file.
     *
     * \throw FileNotFoundException If the specified file was not found or was of the wrong type.
     */
    public void setCurrentlyselectedEF(short fileID) throws FileNotFoundException {
        selectFile( findFile(fileID, SPECIFY_EF) );
        return;
    }

    /**
     * \brief Get the number of the current record for the currently selected EF.
     *
     * \return The record number.
     */
    public short getCurrentRecordNumber() {
        return currentRecordNum;
    }

    /**
     * \brief Set the number of the current record for the currently selected EF.
     *
     * \attention The currently selected EF must be of the class ElementaryFileLinearVariable or a subclass.
     *
     * \param recordID The number of the record. Must be a legal value i.e. in range for the current EF.
     */
    public void setCurrentRecordNumber(short recordID) {
        if ((getCurrentlySelectedEF() instanceof ElementaryFileLinearVariable)
                &&(((ElementaryFileLinearVariable)getCurrentlySelectedEF()).getCurrentRecordCount() > recordID)
                && (recordID >= 0)) {
            currentRecordNum = recordID;
        }
    }

    /**
     * \brief Set the Authentication status of the user.
     *
     * Note: Access control is only forced for operations of the IsoFileSystem class (processXXX methods).
     * It is the responsibility of the applet to enforce security policy for individual file operations,
     * even those that the IsoFileSystem saves references for, if it uses any other method to manipulate
     * files.
     */
    public void setUserAuthenticated(boolean isAuthenticated) {
        this.isUserAuthenticated[0] = isAuthenticated;
    }

    /**
     * \brief Check wether the operation is valid according to the security status of the
     * 			filesystem.
     *
     * If the operation is permitted, this method just returns. If not, it throws an
     * ISOException with a SECURITY STATUS NOT SATISFIED status word. The processing
     * of the current APDU will be aborted.
     *
     * \param file The file the opertaion is executed upon.
     *
     * \param flag_operation A flag of ACL_OP_* to specify the operation.
     *
     * \throw ISOException SW_SECURITY_STATUS_NOT_SATISFIED if the operation is not
     * 			permitted.
     */
    public void authenticateAction(File file, byte flag_operation) throws ISOException {
        if (file == null) {
            return;
        }

        byte acl = file.getACLRequirements(flag_operation);

        if(acl == (byte) 0x00) { // No restrictions.
            return;
        } else if(acl == (byte) 0xFF) { // Never.
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        } else if(acl == (byte) 0x90
                  || (byte)(acl&(byte)0x9F) == (byte)0x10) {
            // PIN required.
            if(isUserAuthenticated[0]) {
                return;
            } else {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
        } else {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    /**
     * \brief Search for the DF with the specified name.
     *
     * \param DFname The array containing the up to 16 byte long DedicatedFile name.
     *
     * \param nameOffset The offset at which the DF name begins in the name array.
     *
     * \param nameLength The length of the DF name.
     *
     * \throw FileNotFoundException If the file was not found.
     *
     * \return The requested DedicatedFile (if found).
     */
    public DedicatedFile findDedicatedFileByName(byte[] DFname, short nameOffset, short nameLength) throws FileNotFoundException {
        if (isName(DFname, nameOffset, nameLength)) {
            return this;
        }
        return super.findDedicatedFileByNameRec(DFname, nameOffset, nameLength);
    }


    /**
     * \brief find the file with the specified file ID.
     *
     * \param fileID the ID of the file.
     *
     * \param flag A flag to specify if the currently selected EF or DF is the target (SPECIFY_EF, SPECIFY_DF, SPECIFY_ANY).
     *
     * \throw FileNotFoundException If the file could not be found.
     *
     * \return The File (if found).
     */
    public File findFile(short fileID, byte flag) throws FileNotFoundException {
        if(fileID == getFileID() && flag != SPECIFY_EF) {
            return this;
        }
        return super.findChildrenRec(fileID, flag);
    }

    /**
     * \brief Set the given file as the selected.
     *
     * If the file is a DedicatedFile, only the currently selected DF is changed.
     * In case of an ElementaryFile the currently selected EF will be the file specified and the
     * currently selected DF will become its parent according to ISO 7816-4, section 7.1.1.
     *
     * \param file The file to select. Must be of DedicatedFile, IsoFileSystem or any subclass of ElementaryFile.
     * 			It should be member of the file system hierarchy (not checked).
     */
    public void selectFile(File file) {
        if(file == null) {
            currentlySelectedFiles[OFFSET_CURRENT_DF] = this;
            currentlySelectedFiles[OFFSET_CURRENT_EF] = null;
        } else if(file instanceof DedicatedFile) {
            currentlySelectedFiles[OFFSET_CURRENT_DF] = file;
        } else if (file instanceof ElementaryFile) {
            currentlySelectedFiles[OFFSET_CURRENT_EF] = file;
            currentlySelectedFiles[OFFSET_CURRENT_DF] = ((ElementaryFile)currentlySelectedFiles[OFFSET_CURRENT_EF]).getParentDF();
            this.currentRecordNum = 0;
        }
        return;
    }

    /**
     * \brief Add a file to the currently selected DedicatedFile.
     *
     * The currently selected DF becomes the parent of the file.
     * The DF's child and the EF's parent relation is being updated.
     *
     * \param file A reference of the file to save.
     *
     * \throw NotEnoughSpaceException If the maximum amount of
     * 			children would have been exceeded.
     */
    public void addFile(File file) throws NotEnoughSpaceException {
        file.setParentDF(getCurrentlySelectedDF());
        getCurrentlySelectedDF().addChildren(file);
        return;
    }


    /**
     * \brief "Safely" instantiate a File according to the provided File Control Information.
     *
     * Used by processCreateFile().
     *
     * \callergraph
     *
     * \param fci The array containing the file control information (FCI) according to
     *				ISO7816-4 table 12. Mandatory Tags: 82, 83. A copy of the FCI will be
     *				made for the new file.
     *
     * \param offset The offset of the FCI information in the array.
     *
     * \param length The length of the FCI information. Should be consistent with the length
     *					field if the FCI (6F) tag.
     *
     * \throw ISOException SW_SECURITY_STATUS_NOT_SATISFIED.
     *
     * \return The new file of the FCI was valid, null else.
     */
    public File getSafeFile(byte[] fci, short offset, short length) throws ISOException {
        short fileID;
        byte fileDescByte;
        final short innerLength, innerOffset;
        short pos, len;

        /* **********************
         * Check FCI structure. *
         ************************/
        // Are we in bounds?
        if((short)(fci.length) <= (short)(offset+length)) {
            return null;
        }

        // FCI must begin with tag "6F". Or we have FCP, tag "62".
        if(fci[(offset)] != (byte) 0x6F
                && fci[(offset)] != (byte) 0x62) {
            return null;
        }

        // length and length-field of outer FCI tag consistency check.
        innerLength = UtilTLV.decodeLengthField(fci, (short)(offset+1));
        if(innerLength != (short)(length-1-UtilTLV.getLengthFieldLength(innerLength))) {
            return null;
        }

        // Let innerOffset point to the first inner TLV entry.
        innerOffset = (short) (offset + 1 + UtilTLV.getLengthFieldLength(innerLength));

        // Now we check for the consistency of the lower level TLV entries.
        if( ! UtilTLV.isTLVconsistent(fci, innerOffset, innerLength) ) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // Extract the FID from the FCI which is passed to the FileXXX contructor and saved
        // separately for performance reasons.
        pos = UtilTLV.findTag(fci, innerOffset, innerLength, (byte) 0x83);
        len = UtilTLV.decodeLengthField(fci, (short)(pos+1));
        if (pos < 0 || len != (short) 2) {
            return null;
        }
        fileID = Util.getShort(fci, (short)(pos+1+UtilTLV.getLengthFieldLength(len)));
        // The fileID must be unique.
        try {
            this.findFile(fileID, SPECIFY_ANY);
            return null;
        } catch( FileNotFoundException e) {

        }

        // Search the ACL tag (86). If the position is -1, then we do not have any ACL and any
        // action may be performed.
        pos = UtilTLV.findTag(fci, innerOffset, innerLength, (byte) 0x86);
        len = UtilTLV.decodeLengthField(fci, (short)(pos+1));
        // If we have an ACL, the length must be 8. (1 access mode byte according to ISO 7816-4
        // tables 16 and 17, followed by 7 security condition bytes according to table 20.)
        // I.e. we require every security condition byte to be present. This eases ACL calculation.
        if(pos > 0 && len != (short)8) {
            return null;
        }

        // Check and get the File Descriptor Byte (ISO 7816-4 table 14).
        pos = UtilTLV.findTag(fci, innerOffset, innerLength, (byte) 0x82);
        len = UtilTLV.decodeLengthField(fci, (short)(pos+1));
        // Ensure position found and correct length:
        if(pos < 0 || len < (short)1 || len > (short)6) {
            return null;
        }
        fileDescByte = fci[(short)(pos+2)];

        byte[] fciEEPROM = null;
        if((fileDescByte & 0x3F) == 0x38) {
            // DF

            // Check the permissions.
            authenticateAction(((DedicatedFile)currentlySelectedFiles[OFFSET_CURRENT_DF]), ACL_OP_CREATE_DF);

            fciEEPROM = new byte[length];
            Util.arrayCopy(fci, offset, fciEEPROM, (short) 0, length);
            return new DedicatedFile(fileID, fciEEPROM);
        } else if((fileDescByte & 0x30) == 0x00) {
            /* EF (Working or Internal) */

            // Check the permissions.
            authenticateAction(((DedicatedFile)currentlySelectedFiles[OFFSET_CURRENT_DF]), ACL_OP_CREATE_EF);

            // Get max record size and number of records.
            // Note: pos is still at the file descriptor byte tag.
            short recordSize = 256; // (assumed) default record size.
            byte maxRecords = 8; // (assumed) default record count.
            switch(fci[(short)(pos+1)]) { // switch on the length: see ISO 7816-4 Table 12, Tag 82.
            case 0x03:
                // max record size is 1 byte long.
                recordSize = fci[(short)(pos+4)];
                break;

            case 0x04:
                // max record size is 2 bytes long.
                recordSize = Util.getShort(fci, (short)(pos+4));
                break;

            case 0x05:
                // max record size is 2 bytes long, number of records is 1 byte long.
                recordSize = Util.getShort(fci, (short)(pos+4));
                maxRecords = fci[(short)(pos+2)];
                break;

            case 0x06:
                // max record size is 2 bytes long, nu,ber of records is 2 bytes long.
                recordSize = Util.getShort(fci, (short)(pos+4));
                if(fci[(short)(pos+6)] == 0x00) {
                    maxRecords = fci[(short)(pos+7)];
                } else {
                    // We only support up to 255 records per file.
                    return null;
                }
                break;

            default:
                // No information given about max record size..
            }

            /* Instantiate the file for the different EF types: */
            switch(fileDescByte & 0x07) {
            case 0x00:
                /* No information given - We don't know what to do. */
                return null;

            case 0x01:
                /* Transparent structure */
                // Get the "data size" tag to determine how many bytes to allocate.
                pos = UtilTLV.findTag(fci, (short)(offset+2), fci[(short)(offset+1)], (byte) 0x81);
                short dataSize = 128; // Assume a default data size.

                if(pos >= 0) {
                    if(fci[(short)(pos+1)] == (byte) 0x02) {
                        dataSize = Util.getShort(fci, (short) (pos+2));
                    } else if(fci[(short)(pos+1)] == (byte) 0x01) {
                        dataSize = fci[(short)(pos+2)];
                    } else {
                        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                    }
                }

                // Instantiate the EF.
                fciEEPROM = new byte[length];
                Util.arrayCopy(fci, offset, fciEEPROM, (short) 0, length);
                return new ElementaryFileTransparent(fileID, fciEEPROM, dataSize);

            case 0x02: // Linear structure, fixed size, no further information: fall through.
            case 0x03:
                /* Linear structure, fixed size, TLV structure (TLV is neither ensured nor interpreted by card.) */
                fciEEPROM = new byte[length];
                Util.arrayCopy(fci, offset, fciEEPROM, (short) 0, length);
                return new ElementaryFileLinearFixed(fileID, fciEEPROM, maxRecords, recordSize);

            case 0x04: // Linear structure, variable size, no further information: fall through.
            case 0x05:
                // Linear structure, varible size, TLV structure (TLV is neither ensured nor interpreted by card.)
                fciEEPROM = new byte[length];
                Util.arrayCopy(fci, offset, fciEEPROM, (short) 0, length);
                return new ElementaryFileLinearVariable(fileID, fciEEPROM, maxRecords);

            case 0x06: // Cyclic structure, fixed size, no further indication: fall through.
            case 0x07:
                // Cyclic structure, fixed size, TLV structure (TLV is neither ensured nor interpreted by card.)
                fciEEPROM = new byte[length];
                Util.arrayCopy(fci, offset, fciEEPROM, (short) 0, length);
                return new ElementaryFileCyclicFixed(fileID, fciEEPROM, maxRecords, recordSize);
            }
            // End EF (Working or internal).
        } else {
            // Not a supported file format.
            return null;
        }
        return null;
    }



    /* **************************************
     * processXXX methods for ISO commands: *
     ****************************************/

    /* ISO 7816-4 */

    /**
     * \brief Process the SELECT (FILE) apdu.
     *
     * This method updates the currently selected EF or DF, according to the parameters in the apdu.
     * Every selection method according to ISO 7816-4 Table 39 is valid.
     * There are limitations of the P2 byte (b8...b1)  at the moment, however:
     * 	- The first or only occurence is the only supported file occurence (b2b1 = 00)
     *	- No FMD is returned. (b4b3 != 10, if b4b3 = 00 then the response only contains the FCP template.)
     *
     * \param apdu The SELECT (FILE) apdu
     *
     * \throw ISOException SW_INCORRECT_P1P2 and SW_FILE_NOT_FOUND.
     */
    public void processSelectFile(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short lc;
        short offset_cdata;
        short fid;
        File fileToSelect = null;

        // Only "first or only occurence" supported at the moment (ISO 7816-4 Table 40).
        if((p2 & 0xF3) != 0x00) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Bytes received must be Lc.
        lc = apdu.setIncomingAndReceive();
        if(lc != apdu.getIncomingLength()) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        offset_cdata = apdu.getOffsetCdata();

        // Select the file.
        switch(p1) {
        case 0x00: /* MF, DF or EF using FID */
            if(lc == 0) {
                fileToSelect = this;
            } else if(lc == 2) {
                // we have a FID
                fid = Util.makeShort(buf[offset_cdata], buf[(short)(offset_cdata+1)]);
                try {
                    fileToSelect = findFile(fid , SPECIFY_ANY);
                } catch(FileNotFoundException e) {
                    ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
                }
            }
            break;
        case 0x01: /* Child DF unsing "DF identifier" (i.e. ID of a DF) */
            fid = Util.makeShort(buf[offset_cdata], buf[(short)(offset_cdata+1)]);
            try {
                fileToSelect = getCurrentlySelectedDF().findChildrenRec(fid, SPECIFY_DF);
            } catch(FileNotFoundException e) {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            }
            break;
        case 0x02: /* EF under the current DF using "EF identifer" (i.e. FID of a EF) */
            fid = Util.makeShort(buf[offset_cdata], buf[(short)(offset_cdata+1)]);
            try {
                fileToSelect = getCurrentlySelectedDF().findChildrenRec(fid, SPECIFY_EF);
            } catch(FileNotFoundException e) {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            }
            break;
        case 0x03: /* parent DF of the current DF */
            if(lc != 0) {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            }
            // The MF ("this") has no parent.
            if(getCurrentlySelectedDF() != this) {
                fileToSelect = getCurrentlySelectedDF().getParentDF();
            } else {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            }
            break;
        case 0x04: /* by DF name */
            try {
                fileToSelect = findDedicatedFileByName(buf, offset_cdata, lc);
            } catch(FileNotFoundException e) {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            }
            break;
        case 0x08: /* Path from MF */
            try {
                fileToSelect = this.findChildrenByPath(buf, offset_cdata, lc);
            } catch(FileNotFoundException e) {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            }
            break;
        case 0x09: /* Path from current DF */
            try {
                fileToSelect = getCurrentlySelectedDF().findChildrenByPath(buf, offset_cdata, lc);
            } catch(FileNotFoundException e) {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            }
            break;
        default:
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        selectFile( fileToSelect );

        /*
         * The file is selected now. We still have to check P2 to see if we need to return any FCI/FCP/FMD information.
         * If we have to, we can use the apdu buffer to save the TLV encoded entries as that is what we want to send back anyway (for performance reasons).
         * We don't use javacardx.framework.tlv.BERTLV as smartcard support is scarce..
         */
        lc = 0; // We re-use lc here for the length of the response data.
        switch(p2 & 0xFC) {
        case 0x00:
            /* Return FCI. */
            // FCP:
            if(fileToSelect.getFileControlInformation() != null) {
                Util.arrayCopy(fileToSelect.getFileControlInformation(), (short) 0, buf, (short) 0, (short) fileToSelect.getFileControlInformation().length);
                lc += (short) fileToSelect.getFileControlInformation().length;
            }
            // FMD:
            // TODO
            // Attention: Copy to buf at position lc, not position 0.
            break;
        case 0x04:
            // Return FCP.
            if(fileToSelect.getFileControlInformation() != null) {
                Util.arrayCopy(fileToSelect.getFileControlInformation(), (short) 0, buf, (short) 0, (short) fileToSelect.getFileControlInformation().length);
                lc += (short) fileToSelect.getFileControlInformation().length;
            }
            break;
        case 0x08:
            // Return FMD.
            // TODO
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            break;
        case 0x0C:
            // Return nothing.
            break;
        }
        if( lc > 0) {
            apdu.setOutgoingAndSend((short) 0, lc);
        }
        return;
    }

    /**
     * \brief Process the READ BINARY APDU.
     *
     * \param apdu The APDU (INS=B0).
     *
     * \throw ISOException SW_FUNC_NOT_SUPPORTED, SW_SECURITY_STATUS_NOT_SATISFIED, SW_INCORRECT_P1P2
     *			SW_FILE_NOT_FOUND and SW_COMMAND_INCOMPATIBLE_WITH_FILE_STRUCTURE.
     */
    public void processReadBinary(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];

        // Check INS: We only support INS=B0 at the moment.
        if(buf[ISO7816.OFFSET_INS] == (byte) 0xB1) {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }

        // We expect a case 2 APDU (CLA|INS|P1|P2|Le)
        if(apdu.setIncomingAndReceive() != (short) 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Check P1 and P2.
        short offset = -1; // offset in data in EF
        ElementaryFile ef = null;
        if((p1 & 0xE0) == 0x80) {
            byte sfi = (byte)(p1 & 0x1F);
            offset = p2;
            try {
                ef = getCurrentlySelectedDF().findChildElementaryFileBySFI(sfi);
            } catch(FileNotFoundException e) {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            }
        } else if((p1 & 0x80) == 0x00) {
            // P1P2 except the most significant bit of P1 form the offset
            // This number can be up to 32767. Exactly what a signed short can hold! ;-)
            offset = (short)((short)(p1 & 0x7F) << (short)8);
            offset |= (short)(p2 & 0x00FF);
            ef = getCurrentlySelectedEF();
        } else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Check Access
        authenticateAction(ef, ACL_OP_READ_SEARCH);

        // EF to read from must be transparent.
        ElementaryFileTransparent efTr = null;
        if(ef instanceof ElementaryFileTransparent) {
            efTr = (ElementaryFileTransparent) ef;
        } else {
            ISOException.throwIt(SW_COMMAND_INCOMPATIBLE_WITH_FILE_STRUCTURE);
        }

        // Le: Length of expected data (i.e. max length of data to read).
        short le = (short)(buf[(short)4] & 0x00FF);
        if(le == 0) {
            le = 256;
        }

        // Offset in bounds?
        if( ((offset) >= efTr.getData().length)
                || (offset < 0) ) {
            ISOException.throwIt(SW_OFFSET_OUTSIDE_EF);
        }

        /*
         * Adjust Le: If it is longer than the actual data, set it to the legnth of the actual data.
         *
         * The host may request all the data (up to 256 Bytes) with Le=00, but the data might be smaller.
         * This is a valid request; we have to send all the data (even if less than 256 Bytes).
         */
        if((short) (le+offset) >= (short) efTr.getData().length) {
            le = (short)((short)(efTr.getData().length) - offset);
        }

        // Read.
        Util.arrayCopy(efTr.getData(), offset, buf, (short) 0, le);

        // Send.
        apdu.setOutgoingAndSend((short) 0, le);
    }


// TODO WRITE BINARY If file lifecycles are to be implemented.

    /**
     * \Brief Process the UPDATE BINARY apdu.
     *
     * This method updates data already present in a transparent EF. The APDU specifies an
     * offset at which the update should start. Either the current EF (P1 most significant
     * bits 100) or an EF specified by a short EF identifier (SFI) under the current DF are
     * altered. At the moment, only INS=D6 APDUs are supported.
     *
     * \param apdu The APDU (INS=D6).
     *
     * \throw ISOException SW_FUNC_NOT_SUPPORTED, SW_SECURITY_STATUS_NOT_SATISFIED, SW_INCORRECT_P1P2
     *			SW_FILE_NOT_FOUND and SW_COMMAND_INCOMPATIBLE_WITH_FILE_STRUCTURE.
     */
    public void processUpdateBinary(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short lc;
        short offset_cdata;

        // Check INS: We only support INS=D6 at the moment.
        if(buf[ISO7816.OFFSET_INS] == (byte) 0xD7) {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }

        // Bytes received must be Lc.
        lc = apdu.setIncomingAndReceive();
        if(lc != apdu.getIncomingLength()) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        offset_cdata = apdu.getOffsetCdata();

        // Check P1 and P2.
        short offset = -1; // offset in data in EF
        ElementaryFile ef = null;
        if((p1 & 0xE0) == 0x80) {
            byte sfi = (byte)(p1 & 0x1F);
            offset = p2;
            try {
                ef = getCurrentlySelectedDF().findChildElementaryFileBySFI(sfi);
            } catch(FileNotFoundException e) {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            }
        } else if((p1 & 0x80) == 0x00) {
            // P1P2 except the most significant bit of P1 form the offset
            // This number can be up to 32767. Exactly what a signed short can hold! ;-)
            offset = (short)((short)(p1 & 0x7F) << (short)8);
            offset |= (short)(p2 & 0x00FF);
            ef = getCurrentlySelectedEF();
        } else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Check permissions.
        authenticateAction(ef, ACL_OP_UPDATE_ERASE);

        // EF to update must be transparent.
        ElementaryFileTransparent efTr = null;
        if(ef instanceof ElementaryFileTransparent) {
            efTr = (ElementaryFileTransparent) ef;
        } else {
            ISOException.throwIt(SW_COMMAND_INCOMPATIBLE_WITH_FILE_STRUCTURE);
        }

        // The data field should contain the new data.
        if(((short) efTr.getData().length >= (short) (offset+lc)) // Check for data array overflow/out-of-bounds.
                && ((short) ((short)32767-offset) >= lc)) { // Check for possible short overflow.
            Util.arrayCopy(buf, offset_cdata, efTr.getData(), offset, lc);
            selectFile(ef);
        } else {
            ISOException.throwIt(SW_OFFSET_OUTSIDE_EF);
        }
    }


// TODO SEARCH BINARY A0 A1
// TODO ERASE BINARY 0E 0F

// TODO If record files are to be used:
// 		- READ RECORD B2 B3
// 		- WRITE RECORD D2
// 		- UPDATE RECORD DC DD
// 		- APPEND RECORD E2
// 		- SEARCH RECORD A2
// 		- ERASE RECORD 0C


    /* ISO 7816-9 */

    /**
     * \brief Process the DELETE FILE apdu.
     *
     * \attention Only deletion by FID is supported. Lc must be 2, the DATA field
     * 				must contain the file ID. P1P2 must be 0000.
     *
     * \todo Add support for other file identification methods as in SELECT.
     *
     * \param apdu The DELETE FILE apdu.
     *
     * \throw ISOException SW_INCORRECT_P1P2, SW_WRONG_LENGTH, SW_FILE_NOT_FOUND and
     *			SW_SECURITY_STATUS_NOT_SATISFIED.
     */
    public void processDeleteFile(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short lc;
        short offset_cdata;
        short fileID;
        File fileToDelete = null;

        // Only P1P2 = 0000 is currently supported.
        // (File identifier must be encoded in the command data field.)
        if( p1 != 0x00 || p2 != 0x00 ) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Bytes received must be Lc.
        lc = apdu.setIncomingAndReceive();
        if(lc != apdu.getIncomingLength()) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        offset_cdata = apdu.getOffsetCdata();

        // One FID in DATA.
        if(lc != 2) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Find the File.
        fileID = Util.getShort(buf, offset_cdata);
        try {
            fileToDelete = findFile(fileID, SPECIFY_ANY);
        } catch (FileNotFoundException e) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }

        // Don't delete the MF.
        if(fileToDelete == this) {
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }

        // Permissions.
        authenticateAction(fileToDelete, ACL_OP_DELETE_SELF);

        // Update current DF before deletion.
        currentlySelectedFiles[OFFSET_CURRENT_DF] = (fileToDelete.getParentDF());
        currentlySelectedFiles[OFFSET_CURRENT_EF] = null;

        // Remove from tree. Garbage collector has already been called by deleteChildren().
        try {
            getCurrentlySelectedDF().deleteChildren(fileID);
        } catch(FileNotFoundException e) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
    }

    /**
     * \brief Process the CREATE FILE apdu.
     *
     * This method creates a file, adds it to the filesystem structure and selects it.
     * Configuration options are taken from the DATA field of the APDU. (I.e. P1 and P2 must be 00.)
     * The data field of the APDU must be 2-level nested TLV encoded. The upper level is the FCI (6F) or FCP (62) tag.
     * The nested information will be added to the file as FCI. Also, the following information is being taken in
     * order to allocate the right ressources:
     *		- The file ID (tag 83)
     *		- The file description byte (tag 82) to determine the type, also following information to determine record
     *			sizes and amounts in case of non-transparent EFs.
     *		- In the case of a transparent EF, the data size (excluding structural information) (tag 80) in order to
     * 			allocate enough space.
     *
     * \param apdu The SELECT (FILE) apdu
     *
     * \throw ISOException SW_INCORRECT_P1P2, SW_DATA_INVALID, SW_FILE_FULL and SW_SECURITY_STATUS_NOT_SATISFIED.
     */
    public void processCreateFile(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short lc;
        short offset_cdata;

        // Only P1P2 = 0000 supported.
        // (File identifier and parameters must be encoded in the command data field.)
        if( p1 != 0x00 || p2 != 0x00 ) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Bytes received must be Lc.
        lc = apdu.setIncomingAndReceive();
        if(lc != apdu.getIncomingLength()) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        offset_cdata = apdu.getOffsetCdata();

        File fileToAdd = getSafeFile(buf, offset_cdata, lc); // getSafeFile performs permission checks.

        // Add the file to the filesystem and select it.
        if(fileToAdd != null) {
            try {
                addFile(fileToAdd);
                selectFile(fileToAdd);
            } catch(NotEnoughSpaceException e) {
                ISOException.throwIt(ISO7816.SW_FILE_FULL);
            }
        } else {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        return;
    }

// TODO If file lifecycles are to be implemented:
// 		- DEACTIVATE FILE 04
// 		- ACTIVATE FILE 44
// 		- TERMINATE DF E6
// 		- TERMINATE EF E8
}
