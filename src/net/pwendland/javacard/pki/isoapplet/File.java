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

import net.pwendland.javacard.pki.isoapplet.UtilTLV;

/**
 * \brief The File class acting as superclass for any file.
 */
public abstract class File {
    private final short fileID;
    private DedicatedFile parentDF;

    final byte[] fci;
    private final short aclPos;

    /* Access Control Operations */
    public static final byte ACL_OP_DELETE_SELF = (byte) 0x01;

    public static final byte ACL_OP_CREATE_DF = (byte) 0x02;
    public static final byte ACL_OP_CREATE_EF = (byte) 0x03;
    public static final byte ACL_OP_DELETE_CHILD = (byte) 0x04;

    public static final byte ACL_OP_WRITE = (byte) 0x05;
    public static final byte ACL_OP_UPDATE_ERASE = (byte) 0x06;
    public static final byte ACL_OP_READ_SEARCH = (byte) 0x07;

    /**
     * \brief Abstract constructor to be called by subclasses.
     *
     * \param fileID The ID of the file.
     *
     * \param fileControlInformation The FCI according to ISO 7816-4 table 12. Necessary tags: 82, 83. No copy is made.
     */
    public File(short fileID, byte[] fileControlInformation) {
        this.fileID = fileID;
        this.parentDF = null;
        this.fci = fileControlInformation;
        // Save the position of the ACL (Value field) in the FCI for performance reasons.
        // If the position is -1, then every action may be performed.
        this.aclPos = UtilTLV.findTag(fci, (short) 2, fci[(short)1], (byte) 0x86);
    }

    /**
     * \brief Get the relevant ACL byte for the operation.
     *
     * \param flag_operation The operation. One of ACL_OP_*.
     *
     * \return The ACL byte.
     */
    public byte getACLRequirements(byte flag_operation) {
        if(aclPos == -1) {
            return (byte) 0x00; // Any operation is allowed if there is no ACL.
        }

        switch(flag_operation) {
        case ACL_OP_DELETE_SELF:
            return fci[(short)(aclPos+3)];

        case ACL_OP_WRITE:
        case ACL_OP_CREATE_DF:
            return fci[(short)(aclPos+7)];

        case ACL_OP_UPDATE_ERASE:
        case ACL_OP_CREATE_EF:
            return fci[(short)(aclPos+8)];

        case ACL_OP_READ_SEARCH:
        case ACL_OP_DELETE_CHILD:
            return fci[(short)(aclPos+9)];

        default:
            return (byte) 0xFF; // No access for unknown actions.
        }
    }

    /**
     * \brief Get the file identifier.
     *
     * \return The file ID.
     */
    public short getFileID() {
        return this.fileID;
    }

    /**
     * \brief Get the parent Dedicated File (DF).
     *
     * \return The parent DF or null if the file had not been added yet.
     */
    public DedicatedFile getParentDF() {
        return this.parentDF;
    }

    /**
     * \brief Set the parent Dedicated File (DF).
     *
     * \param parent the parent DF.
     */
    public void setParentDF(DedicatedFile parent) {
        this.parentDF = parent;
    }

    /**
     * \brief Get the File Control Information (FCI).
     *
     * \return The FCI array.
     */
    public byte[] getFileControlInformation() {
        return this.fci;
    }


}
