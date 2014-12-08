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

import javacard.framework.Util;

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
    public static short findTag(byte[] tlv, short tlvOffset, short tlvLength, byte tag) {
        short tagPos = tlvOffset;
        short len;

        while(tagPos < (short)(tlvLength+tlvOffset-1)) {
            if(tlv[tagPos] == tag) {
                return tagPos;
            }
            len = decodeLengthField(tlv, (short)(tagPos+1));
            // Increase the position by: T length (1), L length, V length.
            // I.e. look at the next Tag, jump over current L and V field.
            // This saves execution time and ensures that no byte from V is misinterpreted.
            tagPos += 1 + getLengthFieldLength(len) + len;
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
        short len;

        while(pos < (short)(length+offset-1)) {
            len = decodeLengthField(tlv, (short)(pos+1));
            if(len < 0) {
                return false;
            }
            pos += 1 + getLengthFieldLength(len) + len;
        }
        return (pos == (short)(offset+length));
    }

    /**
     * \brief Decode the length field of a TLV-entry.
     *
     * The length field itself can be 1, 2 or 3 bytes long:
     * 	- If the length is between 0 and 127, it is 1 byte long.
     * 	- If the length is between 128 and 255, it is 2 bytes long.
     *		The first byte is 0x81 to indicate this.
     *	- If the length is between 256 and 65535, it is 3 bytes long.
     *		The first byte is 0x82, the following 2 contain the actual length.
     *		Note: Only lengths up to 0x7FFF (32767) are supported here, because a short in Java is signed.
     *
     * \param buf The buffer containing the length field.
     *
     * \param offset The offset at where the length field starts.
     *
     * \param length The length of the buffer (buf). This is to prevent that the index gets out of bounds.
     *
     * \return The (positive) length encoded by the length field, or in case of an error, -1.
     */
    public static short decodeLengthField(byte[] buf, short offset) {
        if(buf[offset] == (byte)0x82) { // 256..65535
            // Check for short overflow
            // (In Java, a short is signed: positive values are 0000..7FFF)
            if(buf[(short)(offset+1)] > (byte)0x7F) {
                return -1;
            }
            return Util.getShort(buf, (short)(offset+1));
        } else if(buf[offset] == (byte)0x81) {
            return (short) ( 0x00FF & buf[(short)(offset+1)]);
        } else if(buf[offset] <= (byte)0x7F) {
            return (short) ( 0x00FF & buf[offset]);
        } else {
            return -1;
        }
    }

    /**
     * \brief Get the length of the length field of a TLV-entry.
     *
     * Note: Not the length of the value-field is returned,
     * but the length of the length field itself.
     *
     * \see decodeLengthField()
     *
     * \param length The decoded length from the TLV-entry.
     *
     * \return -1 in case of an error, or the length of the length field.
     */
    public static short getLengthFieldLength(short length) {
        if(length < 0) {
            return -1;
        } else if(length < 128) {
            return 1;
        } else if(length < 256) {
            return 2;
        } else {
            return 3;
        }
    }

    /**
     * \brief Write the tag and length to a buffer.
     *
     * Only the tag and length field are written. The writing of the value field is left to the caller.
     *
     * \param tag A one- or two-byte tag.
     *
     * \param len The length that should be written to the length field.
     *
     * \param out The buffer to write the result to.
     *
     * \param outLen The length of out.
     *
     * \param outOffset The offset at which to start writing the tag.
     *
     * \return -1 in case of an error, or the length that was written.
     */
    public static short writeTagAndLen(short tag, short len, byte[] out, short outOffset) {
        byte tagLen;
        short pos = outOffset;
        short outLen = (short)out.length;

        if((short)(tag & (short)0xFF00) != 0) {
            if((short)(tag & (short)0x1F00) != (short)0x1F00) {
                /* Missing escape marker */
                return -1;
            }
            tagLen = 2;
        } else {
            tagLen = 1;
        }

        if(len < 0) {
            return -1;
        }
        if((short)(tagLen + getLengthFieldLength(len)) > (short)(outLen - outOffset)) {
            return -1;
        }

        if(tagLen == 1) {
            out[pos] = (byte)(tag & (short)0x00FF);
        } else {
            Util.setShort(out, pos, tag);
        }
        pos += tagLen;

        if(len < 128) {
            out[pos++] = (byte)(len & (short)0x007F);
        } else if(len < 256) {
            out[pos++] = (byte)0x81;
            out[pos++] = (byte)(len & (short)0x00FF);
        } else {
            out[pos++] = (byte)0x82;
            Util.setShort(out, pos, len);
            pos += 2;
        }

        return (short)(pos - outOffset);
    }

}
