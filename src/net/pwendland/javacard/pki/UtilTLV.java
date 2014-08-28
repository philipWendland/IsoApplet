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

/**
 * \brief Utility class for TLV-realted operations.
 */
public class UtilTLV {

    /** \brief Find the position of the tag at level 1.
     *
     * \attention This method only searches level 1 of TLV encoded arrays (i.e. no nested TLVs are searched).
     *
     * \param tlv The array containing the TLV-encoded object to search.
     *
     * \param tlvOffset The position at which the TLV structure begins.
     *
     * \param tlvLength The length of the TLV structure.
     *
     * \param tag The tag to search for.
     *
     * \return The position of the tag if found or -1.
     */
    public static short findTag(byte[] tlv, short tlvOffset, byte tlvLength, byte tag) {
        short tagPos = tlvOffset;
        while(tagPos < (short)(tlvLength+tlvOffset-1)) {
            if(tlv[tagPos] == tag) {
                return tagPos;
            }
            // Increase the position by the length of the tlv currently looked at plus 2.
            // I.e. look at the next Tag, jump over current L and V field.
            // This saves execution time and ensures that no byte from V is misinterpreted.
            tagPos += (short) (tlv[(short) (tagPos+1)] + 2);
        }
        return -1;
    }

    /**
     * \brief Check the consistency of the TLV structure.
     *
     * Basically, we jump from one tag to the next. At the end, we must be at the position
     * where the next tag would be, if it was there. If the position is any other than that,
     * the TLV structure is not consistent.
     *
     * \param tlv The array containing the TLV-encoded object to search.
     *
     * \param offset The position at which the TLV structure begins.
     *
     * \param length The length of the TLV structure.
     *
     * \return True if the TLV structure is valid, else false.
     */
    public static boolean isTLVconsistent(byte[] tlv, short offset, short length) {
        short pos = offset;
        while(pos < (short)(length+offset-1)) {
            pos += (short) (tlv[(short)(pos+1)] + 2);
        }
        return (pos == (short)(offset+length));
    }
}
