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
 * \brief The ElementaryFileCyclicFixed class.
 *
 * It stores records of a fixed size and overwrites the oldest record if the maximum number of records is exceeded.
 */
public class ElementaryFileCyclicFixed extends ElementaryFileLinearFixed {
    byte currentRecordPos;

    /**
     * \brief Instantiate a new cyclic EF (fixed record size). No data is being added at this point.
     *
     * \param fileID The ID of the file.
     *
     * \param fileControlInformation The array of bytes containing the valid (!) File Control Information.
     *				No Copy is made.
     *
     * \param maxRecords The maximum amount of saved records before overwriting happens.
     *
     * \param recordLength The length of the fixed-size records.
     *
     * \attention No copy of the FCI is made. Do not pass any buffer that is altered
     *				later (e.g. the apdu buffer). Max length 257 bytes as the length
     *				of the FCI Tag (6F) must be a byte.
     *
     * \attention To be safe, use IsoFilesystem.getSafeFile() to instantiate files.
     *
     * \throw IllegalArgumentException If necessary tags in the FCI are missing.
     */
    public ElementaryFileCyclicFixed(short fileID, byte[] fileControlInformation, byte maxRecords, short recordLength) {
        super(fileID, fileControlInformation, maxRecords, recordLength);
        this.currentRecordPos = 0;
    }

    /**
     * \brief Add a record to this cyclic EF (fixed record size).
     *
     * \attention No record will be added if it is of the wrong size.
     *		Make sure that the record to add is of the correct length (e.g. by using getRecordLength() beforehand).
     *
     * \attention As this file is cyclic, the oldest record might get overwritten.
     *
     * \param record The byte array containing the data to add. Must be of the right size.
     *
     * \return 	true 	If the record had been added.
     *			false	An error occurred, no record had been added.
     */
    @Override
    public boolean addRecord(byte[] record) {
        if(record.length == super.getRecordLength()) {
            // Create a new record with the byte array as data and append it to the records array.
            records[currentRecordPos] = new Record(record);
            // Update the current position (cyclic/modulo operation).
            currentRecordPos = (byte)((currentRecordPos + (byte) 1) % (byte) records.length);
            // Only increase currentRecordCount if the array was not full before the operation.
            // (If it was full, the oldest record had been overwritten, so the amount of records did not change.)
            currentRecordCount = currentRecordCount == (byte) records.length ? currentRecordCount : (byte) (currentRecordCount + 1);
            return true;
        }
        return false;
    }

}
