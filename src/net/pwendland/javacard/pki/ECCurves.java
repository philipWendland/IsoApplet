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
 * \brief A helper class containing EC parameters.
 */
public abstract class ECCurves {
    public static final short LENGTH_EC_FP_256 = 256;

    /* Brainpool P192r1 - see RFC 5639 */
    public static final byte[] EC_BRAINPOOLP192R1_PARAM_P = {
        (byte) 0xC3, (byte) 0x02, (byte) 0xF4, (byte) 0x1D,
        (byte) 0x93, (byte) 0x2A, (byte) 0x36, (byte) 0xCD,
        (byte) 0xA7, (byte) 0xA3, (byte) 0x46, (byte) 0x30,
        (byte) 0x93, (byte) 0xD1, (byte) 0x8D, (byte) 0xB7,
        (byte) 0x8F, (byte) 0xCE, (byte) 0x47, (byte) 0x6D,
        (byte) 0xE1, (byte) 0xA8, (byte) 0x62, (byte) 0x97
    };
    public static final byte[] EC_BRAINPOOLP192R1_PARAM_A = {
        (byte) 0x6A, (byte) 0x91, (byte) 0x17, (byte) 0x40,
        (byte) 0x76, (byte) 0xB1, (byte) 0xE0, (byte) 0xE1,
        (byte) 0x9C, (byte) 0x39, (byte) 0xC0, (byte) 0x31,
        (byte) 0xFE, (byte) 0x86, (byte) 0x85, (byte) 0xC1,
        (byte) 0xCA, (byte) 0xE0, (byte) 0x40, (byte) 0xE5,
        (byte) 0xC6, (byte) 0x9A, (byte) 0x28, (byte) 0xEF
    };
    public static final byte[] EC_BRAINPOOLP192R1_PARAM_B = {
        (byte) 0x46, (byte) 0x9A, (byte) 0x28, (byte) 0xEF,
        (byte) 0x7C, (byte) 0x28, (byte) 0xCC, (byte) 0xA3,
        (byte) 0xDC, (byte) 0x72, (byte) 0x1D, (byte) 0x04,
        (byte) 0x4F, (byte) 0x44, (byte) 0x96, (byte) 0xBC,
        (byte) 0xCA, (byte) 0x7E, (byte) 0xF4, (byte) 0x14,
        (byte) 0x6F, (byte) 0xBF, (byte) 0x25, (byte) 0xC9
    };
    public static final byte[] EC_BRAINPOOLP192R1_PARAM_G  = {
        // fixed point of the curve: G(x,y)
        // Uncompressed.
        (byte) 0x04,
        // Coordinates of X.
        (byte) 0xC0, (byte) 0xA0, (byte) 0x64, (byte) 0x7E,
        (byte) 0xAA, (byte) 0xB6, (byte) 0xA4, (byte) 0x87,
        (byte) 0x53, (byte) 0xB0, (byte) 0x33, (byte) 0xC5,
        (byte) 0x6C, (byte) 0xB0, (byte) 0xF0, (byte) 0x90,
        (byte) 0x0A, (byte) 0x2F, (byte) 0x5C, (byte) 0x48,
        (byte) 0x53, (byte) 0x37, (byte) 0x5F, (byte) 0xD6,
        // Coordinates of Y.
        (byte) 0x14, (byte) 0xB6, (byte) 0x90, (byte) 0x86,
        (byte) 0x6A, (byte) 0xBD, (byte) 0x5B, (byte) 0xB8,
        (byte) 0x8B, (byte) 0x5F, (byte) 0x48, (byte) 0x28,
        (byte) 0xC1, (byte) 0x49, (byte) 0x00, (byte) 0x02,
        (byte) 0xE6, (byte) 0x77, (byte) 0x3F, (byte) 0xA2,
        (byte) 0xFA, (byte) 0x29, (byte) 0x9B, (byte) 0x8F
    };
    public static final byte[] EC_BRAINPOOLP192R1_PARAM_R  = {
        // Order of G - "q"
        (byte) 0xC3, (byte) 0x02, (byte) 0xF4, (byte) 0x1D,
        (byte) 0x93, (byte) 0x2A, (byte) 0x36, (byte) 0xCD,
        (byte) 0xA7, (byte) 0xA3, (byte) 0x46, (byte) 0x2F,
        (byte) 0x9E, (byte) 0x9E, (byte) 0x91, (byte) 0x6B,
        (byte) 0x5B, (byte) 0xE8, (byte) 0xF1, (byte) 0x02,
        (byte) 0x9A, (byte) 0xC4, (byte) 0xAC, (byte) 0xC1
    };
    public static final short EC_BRAINPOOLP192R1_PARAM_K  = (short) 1; // Cofactor - "h"


    /* secp256r1 / prime256v1 */
    public static final byte[] EC_PRIME256V1_PARAM_P = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
    };

    public static final byte[] EC_PRIME256V1_PARAM_A = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFC
    };

    public static final byte[] EC_PRIME256V1_PARAM_B = {
        (byte) 0x5A, (byte) 0xC6, (byte) 0x35, (byte) 0xD8,
        (byte) 0xAA, (byte) 0x3A, (byte) 0x93, (byte) 0xE7,
        (byte) 0xB3, (byte) 0xEB, (byte) 0xBD, (byte) 0x55,
        (byte) 0x76, (byte) 0x98, (byte) 0x86, (byte) 0xBC,
        (byte) 0x65, (byte) 0x1D, (byte) 0x06, (byte) 0xB0,
        (byte) 0xCC, (byte) 0x53, (byte) 0xB0, (byte) 0xF6,
        (byte) 0x3B, (byte) 0xCE, (byte) 0x3C, (byte) 0x3E,
        (byte) 0x27, (byte) 0xD2, (byte) 0x60, (byte) 0x4B
    };

    public static final byte[] EC_PRIME256V1_PARAM_G = {
        // uncompressed
        (byte) 0x04,
        // x
        (byte) 0x6B, (byte) 0x17, (byte) 0xD1, (byte) 0xF2,
        (byte) 0xE1, (byte) 0x2C, (byte) 0x42, (byte) 0x47,
        (byte) 0xF8, (byte) 0xBC, (byte) 0xE6, (byte) 0xE5,
        (byte) 0x63, (byte) 0xA4, (byte) 0x40, (byte) 0xF2,
        (byte) 0x77, (byte) 0x03, (byte) 0x7D, (byte) 0x81,
        (byte) 0x2D, (byte) 0xEB, (byte) 0x33, (byte) 0xA0,
        (byte) 0xF4, (byte) 0xA1, (byte) 0x39, (byte) 0x45,
        (byte) 0xD8, (byte) 0x98, (byte) 0xC2, (byte) 0x96,
        // y
        (byte) 0x4F, (byte) 0xE3, (byte) 0x42, (byte) 0xE2,
        (byte) 0xFE, (byte) 0x1A, (byte) 0x7F, (byte) 0x9B,
        (byte) 0x8E, (byte) 0xE7, (byte) 0xEB, (byte) 0x4A,
        (byte) 0x7C, (byte) 0x0F, (byte) 0x9E, (byte) 0x16,
        (byte) 0x2B, (byte) 0xCE, (byte) 0x33, (byte) 0x57,
        (byte) 0x6B, (byte) 0x31, (byte) 0x5E, (byte) 0xCE,
        (byte) 0xCB, (byte) 0xB6, (byte) 0x40, (byte) 0x68,
        (byte) 0x37, (byte) 0xBF, (byte) 0x51, (byte) 0xF5
    };

    public static final byte[] EC_PRIME256V1_PARAM_R = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xBC, (byte) 0xE6, (byte) 0xFA, (byte) 0xAD,
        (byte) 0xA7, (byte) 0x17, (byte) 0x9E, (byte) 0x84,
        (byte) 0xF3, (byte) 0xB9, (byte) 0xCA, (byte) 0xC2,
        (byte) 0xFC, (byte) 0x63, (byte) 0x25, (byte) 0x51
    };

    public static final short EC_PRIME256V1_PARAM_K = (short) 1;

}
