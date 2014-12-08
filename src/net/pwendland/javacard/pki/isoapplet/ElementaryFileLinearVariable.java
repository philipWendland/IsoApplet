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

/**
 * \brief The ElementaryFileLinearVariable class.
 *
 * It stores linear records of variable size.
 *
 * \todo Find record methods?
 */
public class ElementaryFileLinearVariable extends ElementaryFile {
    Record[] records;
    byte currentRecordCount;

    /**
     * \brief Instantiate a new linear EF (variable record size). No data is being added at this point.
     *
     * \param fileControlInformation The array of bytes containing the valid (!) File Control Information.
     *				It must contain the File ID (Tag 83). No Copy is made.
     *
     * \param maxRecords The maximum amount of saved records.
     *
     * \attention No copy of the FCI is made. Do not pass any buffer that is altered
     *				later (e.g. the apdu buffer). Max length 257 bytes as the length
     *				of the FCI Tag (6F) must be a byte.
     *
     * \attention To be safe, use FileFactory.getSafeFile() to instantiate files.
     *
     * \throw IllegalArgumentException If necessary tags in the FCI are missing.
     */
    public ElementaryFileLinearVariable(short fileID, byte[] fileControlInformation, byte maxRecords) {
        super(fileID, fileControlInformation);
        this.records = new Record[maxRecords];
        this.currentRecordCount = 0;
    }

    /**
     * \brief Get the amount of currently saved records.
     *
     * \return The amount of records.
     */
    public byte getCurrentRecordCount() {
        return this.currentRecordCount;
    }

    /**
     * \brief Add a record.
     *
     * \param record The data to save as record.
     *
     * \return 	true 	If the record had been added.
     *			false	An error occurred, no record had been added.
     */
    public boolean addRecord(byte[] record) {
        if(records.length == currentRecordCount) {
            return false;
        }
        // Create a new Record with the byte array as data and append it to the records array, increasing currentRecordCount.
        records[currentRecordCount++] = new Record(record);
        return true;
    }

    /**
     * \brief Get the byte representation (data) of the record.
     *
     * \param The number of the record. This relates to the order in which records have been added.
     *
     * \return The byte representation of the specified record.
     */
    public byte[] getRecordData (byte recordNum) {
        if((recordNum < 0) || (recordNum > currentRecordCount)) {
            return null;
        }
        return this.records[recordNum].data;
    }

}

