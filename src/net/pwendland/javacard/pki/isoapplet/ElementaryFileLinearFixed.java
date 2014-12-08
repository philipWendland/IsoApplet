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
 * \brief The ElementaryFileLinearFixed class.
 *
 * It stores linear fixed-size records.
 */
public class ElementaryFileLinearFixed extends ElementaryFileLinearVariable {
    private final short recordLength;

    /**
     * \brief Instantiate a new linear EF (fixed record size). No data is being added at this point.
     *
     * \param fileID The ID of the file.
     *
     * \param fileControlInformation The array of bytes containing the valid (!) File Control Information.
     *				No Copy is made.
     *
     * \param maxRecords The maximum amount of saved records.
     *
     * \param recordLength The length of the fixed-size records.
     *
     * \attention No copy of the FCI is made. Do not pass any buffer that is altered
     *				later (e.g. the apdu buffer). Max length 257 bytes as the length
     *				of the FCI Tag (6F) must be a byte.
     *
     * \attention To be safe, use FileFactory.getSafeFile() to instantiate files.
     *
     * \throw IllegalArgumentException If necessary tags in the FCI are missing.
     */
    public ElementaryFileLinearFixed(short fileID, byte[] fileControlInformation, byte maxRecords, short recordLength) {
        super(fileID, fileControlInformation, maxRecords);
        this.recordLength = recordLength;
    }

    /**
     * \brief Get the record length.
     *
     * \return The length of any attached record.
     */
    public short getRecordLength() {
        return this.recordLength;
    }

    /**
     * \brief Add a record to this EF (fixed record size).
     *
     * \attention No record will be added if it is of the wrong size.
     * 		Make sure that the record to add is of the correct length (e.g. by using getRecordLength() beforehand).
     *
     * \attention Only references are being stored, no copy is made (for perfomance reasons).
     *
     * \param record The byte array containing the data to save.
     *
     * \return 	true 	If the record had been added.
     *			false	An error occurred, no record had been added.
     */
    @Override
    public boolean addRecord(byte[] record) {
        if(records.length == currentRecordCount) {
            // No space left.
            return false;
        }
        if(record.length == recordLength) {
            // Create a new Record with the byte array as data and append it to the records array, increasing currentRecordCount.
            records[currentRecordCount++] = new Record(record);
            return true;
        } else {
            return false;
        }
    }

}

