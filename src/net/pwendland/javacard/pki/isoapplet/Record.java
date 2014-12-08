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
 * \brief A Record.
 *
 * This class is necessary because multidimensional arrays are not supported by the JCVM.
 */
public class Record {
    byte[] data;

    /**
     * \brief Constructor.
     *
     * \param data The byte array to store. No copy is made.
     */
    Record(byte[] data) {
        this.data = data;
    }

    /**
     * \brief Constructor.
     *
     * A new byte array is being allocated. Use the data-field to fill it up with data.
     *
     * \param size The size of the data array.
     */
    Record(short size) {
        this.data = new byte[size];
    }
}

