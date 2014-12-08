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
 * \brief The FileNotFoundException class.
 *
 * Should be thrown whenever a specified file could not be found.
 * This class is a singleton in order to save resources.
 *
 * \attention This singleton is not thread-safe.
 */
public class FileNotFoundException extends Exception {
    public static FileNotFoundException instance;

    /**
     * \brief Private access constructor (Singleton pattern).
     */
    private FileNotFoundException() {

    }

    /**
     * \brief Get the instance.
     *
     * \return The FileNotFoundException instance.
     */
    public static FileNotFoundException getInstance() {
        if(instance == null) {
            instance = new FileNotFoundException();
        }
        return instance;
    }

}
