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
 * \brief The ElementaryFileTransparent class.
 *
 * It stores a single byte array that is not being interpreted by the filesystem.
 */
public class ElementaryFileTransparent extends ElementaryFile {
    byte[] data;

    /**
     * \brief Instantiate a new transparent EF and store a reference to the data.
     *
     * \param fileControlInformation The array of bytes containing the valid (!) File Control Information.
     *				No Copy is made.
     *
     * \param data The byte array to be saved. No copy is made, only a reference is stored.
     *
     * \attention No copy of the FCI is made. Do not pass any buffer that is altered
     *				later (e.g. the apdu buffer). Max length 257 bytes as the length
     *				of the FCI Tag (6F) must be a byte.
     *
     * \attention To be safe, use FileFactory.getSafeFile() to instantiate files.
     *
     * \throw IllegalArgumentException If necessary tags in the FCI are missing.
     */
    public ElementaryFileTransparent(short fileID, byte[] fileControlInformation, byte[] data) {
        super(fileID, fileControlInformation);
        this.data = data;
    }

    /**
     * \brief Instantiate a new transparent EF and allocate a new data array of the given length.
     *
     * No actual data is being added at this point. Call getData() the get a reference and fill the array.
     *
     * \para, fileID The ID of the file.
     *
     * \param fileControlInformation The array of bytes containing the valid (!) File Control Information.
     *				No Copy is made.
     *
     * \param dataLength The length of the data array to allocate.
     *
     * \attention No copy of the FCI is made. Do not pass any buffer that is altered
     *				later (e.g. the apdu buffer). Max length 257 bytes as the length
     *				of the FCI Tag (6F) must be a byte.
     *
     * \attention To be safe, use FileFactory.getSafeFile() to instantiate files.
     *
     * \throw IllegalArgumentException If necessary tags in the FCI are missing.
     */
    public ElementaryFileTransparent(short fileID, byte[] fileControlInformation, short dataLength) {
        super(fileID, fileControlInformation);
        this.data = new byte[dataLength];
    }

    /**
     * \brief Get a reference to the data of this file.
     *
     * After obtraining the reference, even write operations can directly performed i.e.
     * the actual data of the file can be changed using the reference.
     *
     * \return The reference to the data.
     */
    public byte[] getData() {
        return data;
    }

}
