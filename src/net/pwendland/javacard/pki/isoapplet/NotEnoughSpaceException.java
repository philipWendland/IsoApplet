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
 * \brief Exception class.
 *
 * This class is a singleton in order to save resources.
 *	Should be thrown whenever:
 *	- A limit for the maximum amount of children of a DedicatedFile is exceeded.
 *	- An array can not hold that amount of data.
 *	- Memory allocation failed due to full RAM/EEPROM.
 *
 * \attention This singleton is not thread-safe.
 */
public class NotEnoughSpaceException extends Exception {
    public static NotEnoughSpaceException instance;


    /**
     * \brief Private access constructor (Singleton pattern).
     */
    private NotEnoughSpaceException() {

    }

    /**
     * \brief Get the instance.
     *
     * \return The FileNotFoundException instance.
     */
    public static NotEnoughSpaceException getInstance() {
        if(instance == null) {
            instance = new NotEnoughSpaceException();
        }
        return instance;
    }
}
