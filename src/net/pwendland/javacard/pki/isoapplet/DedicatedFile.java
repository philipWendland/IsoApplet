/*
 * IsoApplet: A Java Card PKI applet aiming for ISO 7816 compliance.
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

import javacard.framework.*;
import net.pwendland.javacard.pki.isoapplet.UtilTLV;

/**
 * \brief The DedicatedFile class.
 *
 * This class acts as a container for any File subclass except the IsoFileSystem class itself. It is equivalent
 * to the ISO "Dedicated File".
 * Children are stored as references. This means that if a File is being altered after it was added as child,
 * also the child is effectively altered as it is the same object.
 *
 * The size of the array storing the references to the children can be set before compilation.
 * Also, this class tries to increase the size until a maximum value. If you do not want that kind of behavior,
 * set CHILDREN_COUNT_MAX to the same value as CHILDREN_COUNT_START.
 */
public class DedicatedFile extends File {
    private static final short CHILDREN_COUNT_START = 10;
    private static final short CHILDREN_COUNT_MAX = 30; // set to max. 16383

    public static final byte SPECIFY_EF = 0x01;
    public static final byte SPECIFY_DF = 0x02;
    public static final byte SPECIFY_ANY = 0x03;

    private byte currentNumChildren;
    private File[] children;


    /**
     * \brief Instantiate a new DedicatedFile.
     *
     * \param fileID The file ID. Should be unique inside the filesystem.
     *
     * \param fileControlInformation The array of bytes containing the valid (!) File Control Information.
     *				It must contain the File ID (Tag 83). No Copy is made.
     *
     * \attention No copy of the FCI is made. Do not pass any buffer that is altered
     *				later (e.g. the apdu buffer). Max length 257 bytes as the length
     *				of the FCI Tag (6F) must be a byte.
     *
     * \attention To be safe, use IsoFilesystem.getSafeFile() to instantiate files.
     *
     * \return The DedicatedFile.
     */
    public DedicatedFile(short fileID, byte[] fileControlInformation) {
        super(fileID, fileControlInformation);
        this.currentNumChildren = 0;
        this.children = new File[CHILDREN_COUNT_START];
    }

    /**
     * \brief Check if this is the name of this DedicatedFile.
     *
     * \param name The array containing the name to compare with the file's name.
     *
     * \param offset The offset at where the name begins.
     *
     * \param length The length of the name.
     *
     * \return false if the DF has no name or the names do not match,
     *			true else.
     */
    public boolean isName(byte[] name, short offset, short length) {
        // Find the position of the DF name tag (84) in the FCI.
        short namePos = UtilTLV.findTag(fci, (short)2, fci[(short)1], (byte) 0x84);
        if(namePos < 0) {
            // This DF has no name.
            return false;
        } else {
            // This DF has a name.
            if(length != UtilTLV.decodeLengthField(fci, (short)(namePos+1))) {
                // The names do not have equal length.
                return false;
            } else {
                return ( (byte)0 == Util.arrayCompare(name, offset, fci,
                                                      (short)(namePos+1+UtilTLV.getLengthFieldLength(length)), length) );
            }
        }
    }

    /**
     * \brief Get the amount of children under this Dedicated File.
     *
     * \return The amount of children under this DF.
     */
    public byte getChildrenCount() {
        return this.currentNumChildren;
    }

    /**
     * \brief Get a children of this Dedicated File.
     *
     * This method returns the specified children of this DF. Can be used in conjunction with getChildrenCount()
     * to iterate over all children.
     *
     * \param num The number of the children, starting at 0 to getChildrenCount(). The references can change when
     *				children had been deleted.
     *
     * \throw FileNotFoundException If the specified file was not found unter this DF.
     *
     * \return The children file if present. May be a DedicatedFile or any non-abstract ElementaryFile subclass.
     */
    public File getChildren(byte num) throws FileNotFoundException {
        if(num >= this.currentNumChildren) {
            throw FileNotFoundException.getInstance();
        }
        return children[num];
    }

    /**
     * \brief Delete a direct children of this DF.
     *
     * This method requests garbage collection.
     *
     * \param fileID The file ID of the children to delete.
     *
     * \throw FileNotFoundException It no children has the given fileID.
     */
    public void deleteChildren(short fileID) throws FileNotFoundException {
        short childNum = -1;
        short i;

        for(i = 0; i < currentNumChildren; i++) {
            if(fileID == children[i].getFileID()) {
                childNum = i;
                break;
            }
        }

        if(childNum == -1) {
            throw FileNotFoundException.getInstance();
        }

        children[childNum] = null;
        currentNumChildren--; // We have one less children now.

        // Fill up empty field in children array.
        // The last children is one ahead, so it is at currentNumChildren.
        if(childNum < currentNumChildren) {
            children[childNum] = children[currentNumChildren];
        }

        // Clean up the old file object.
        JCSystem.requestObjectDeletion();
    }

    /**
     * \brief Add a children to this DF.
     *
     * \param children The children to add. May be a DedicatedFile or any non-abstract ElemetaryFile subclass.
     *
     * \throw NotEnoughSpaceException If CHILDREN_COUNT_MAX is reached.
     */
    public void addChildren(File childFile) throws NotEnoughSpaceException {
        // First we have to check for enough space.
        if(currentNumChildren >= (short)children.length) {
            File[] newChildren = null;
            // The array is full - we try to increase the size.
            if((short)(children.length * 2) <= CHILDREN_COUNT_MAX) {
                // Doubling the size is possible.
                newChildren = new File[(short)(children.length * 2)];
                copyFileArrayRefs(children, newChildren);
            } else {
                // Doubling not possible - try to at least increase to CHILDREN_COUNT_MAX.
                if(currentNumChildren < CHILDREN_COUNT_MAX) {
                    newChildren = new File[CHILDREN_COUNT_MAX];
                    copyFileArrayRefs(children, newChildren);
                } else {
                    // CHILDREN_COUNT_MAX exceeded. No "space" left. Fail.
                    throw NotEnoughSpaceException.getInstance();
                }
            }
            children = newChildren; // Initial children array is now garbage.
            JCSystem.requestObjectDeletion();
        } // We have enough space (now).
        children[currentNumChildren++] = childFile;
        return;
    }

    /**
     * \brief Copies the references from one File array to the other.
     *
     * \attention Although only references are copied, this is probably still quite expensive because
     * writing to EEPROM is. Only use this for operations that are not called often (Creating and deleting files etc.).
     *
     * \param src The source File array to copy from.
     *
     * \param dest The destination File array to copy to. It MUST be at least of size of the src array.
     */
    private static void copyFileArrayRefs(File[] src, File[] dest) {
        short i = 0;
        short length = src.length > dest.length ? (short)dest.length : (short)src.length;

        for(i=0; i < length; i++) {
            dest[i] = src[i];
        }
        return;
    }


    /**
     * \brief Find the Elementary File directly under this DF with the specified file ID.
     *
     * \attention This is not a recursive search operation.
     *
     * \param fileID The file ID of the EF to search.
     *
     * \throw FileNotFoundException If the specified file was not found unter this DF.
     *
     * \return The file if it was found.
     */
    public ElementaryFile findChildElementaryFile (short fileID) throws FileNotFoundException {
        short i = 0;
        for(i=0; i < currentNumChildren; i++) {
            if(children[i].getFileID() == fileID) {
                // File ID is matching, perform a type check and return
                if(children[i] instanceof ElementaryFile) {
                    return (ElementaryFile) children[i];
                }
                // Should not happen: The elementary file that is being searched for is not a elementary file.
                // (i.e. the fileID points to a DF.)
                throw FileNotFoundException.getInstance();
            }
        }
        throw FileNotFoundException.getInstance();
    }

    /**
     * \brief Find the Elementary File directly under this DF using the Short EF identifer.
     *
     * \param sfi The Short EF identifier (5 least significant bits).
     *
     * \throw FileNotFoundException If the File could not be found.
     *
     * \return The file if it was found.
     */
    public ElementaryFile findChildElementaryFileBySFI (byte sfi) throws FileNotFoundException {
        if((sfi & 0xE0) > (byte) 0) {
            throw FileNotFoundException.getInstance();
        }
        short i;
        for(i=0; i < currentNumChildren; i++) {
            if(children[i] instanceof ElementaryFile &&
                    ((ElementaryFile)children[i]).getShortFileID() == sfi) {
                return (ElementaryFile) children[i];
            }
        }
        throw FileNotFoundException.getInstance();
    }

    /**
     * \brief Find the Dedicated File directly under this DF with the specified file ID.
     *
     * \attention This is not a recursive search operation.
     *
     * \param fileID The file ID of the DF to search
     *
     * \throw FileNotFoundException If the specified file was not found unter this DF.
     *
     * \return The file if it was found.
     */
    public DedicatedFile findChildDedicatedFile(short fileID) throws FileNotFoundException {
        short i;
        for(i=0; i < currentNumChildren; i++) {
            if(children[i].getFileID() == fileID) {
                // File ID is matching, perform a type check and return
                if(children[i] instanceof DedicatedFile) {
                    return (DedicatedFile) children[i];
                }
                // Should not happen: The dedicated file that is being searched for is not a dedicated file.
                // (i.e. the fileID points to a EF.)
                throw FileNotFoundException.getInstance();
            }
        }
        throw FileNotFoundException.getInstance();
    }

    /**
     * \brief Recursively search the children of this file using the DedicatedFile name.
     *
     * \param name The DF name of at most 16 bytes according to ISO.
     *
     * \param nameOffset The position in the name array at which the name beigns.
     *
     * \param nameLength The length of the name
     *
     * \throw FileNotFoundException If the specified file was not found among all (sub-)children of this file.
     *
     * \return A reference to the DedicatedFile if found.
     */
    public DedicatedFile findDedicatedFileByNameRec(byte[] name, short nameOffset, short nameLength) throws FileNotFoundException {
        short i;
        for(i=0; i < currentNumChildren; i++) {
            if(children[i] instanceof DedicatedFile) {
                if(((DedicatedFile)children[i]).isName(name, nameOffset, nameLength)) {
                    return (DedicatedFile) children[i];
                }
                try {
                    return ((DedicatedFile)children[i]).findDedicatedFileByNameRec(name, nameOffset, nameLength);
                } catch(FileNotFoundException e) {
                    // Ignore this exception until the last children has unsuccessfully been visited.
                }
            }
        }
        throw FileNotFoundException.getInstance();
    }

    /**
     * \brief Recursively search the children of this file using the file ID.
     *
     * \param fileID The file ID of the file to search for.
     *
     * \throw FileNotFoundException If the specified file was not found among all (sub-)children of this file.
     *
     * \return A reference to the File if found.
     */
    public File findChildrenRec(short fileID, byte flag) throws FileNotFoundException {
        short i;
        for(i=0; i < currentNumChildren; i++) {
            if(children[i].getFileID() == fileID) {
                if((flag == SPECIFY_ANY)
                        || (flag == SPECIFY_DF && children[i] instanceof DedicatedFile)
                        || (flag == SPECIFY_EF && children[i] instanceof ElementaryFile)) {
                    return children[i];
                } else {
                    // File with specified FID and requested file type do not match.
                    throw FileNotFoundException.getInstance();
                }
            }
            if(children[i] instanceof DedicatedFile) {
                try {
                    return ((DedicatedFile)children[i]).findChildrenRec(fileID, flag);
                } catch(FileNotFoundException e) {
                    // Ignore this exception until the last children has unsuccessfully been visited.
                }
            }
        }
        throw FileNotFoundException.getInstance();
    }

    /**
     * \brief Find the children using the specified path.
     *
     * \param path The byte array containing the path. This is a concatenation of File IDs. A fileID is 2 bytes long.
     *
     * \param pathOffset The position at which the path begins. It starts with children of this file.
     *
     * \param pathLength The length of the path in bytes. Two times the FIDs contained.
     *
     * \throw FileNotFoundException If the path does not lead to a file.
     *
     * \return The File if found.
     */
    public File findChildrenByPath(byte[] path, short pathOffset, short pathLength) throws FileNotFoundException {
        byte childPos;
        short pathPos;
        short nextFileID;

        DedicatedFile df = this;
        for(pathPos=pathOffset; pathPos < (short) ((pathLength+pathOffset)-1); pathPos+=2) {
            nextFileID = Util.getShort(path, pathPos);
            for(childPos=0; childPos < df.getChildrenCount(); childPos++) {
                if(nextFileID == df.getChildren( childPos ).getFileID()) {
                    // We found the next node in the path.
                    if(pathPos == (short) (pathOffset+pathLength-2)) {
                        // It is the last File in the path with a matching FID.
                        // We are done.
                        return df.getChildren(childPos);
                    } else if(df.getChildren( childPos ) instanceof DedicatedFile) {
                        // We still have to search for children.
                        // Luckily, the last file we found is a DF. :-)
                        df = (DedicatedFile) df.getChildren( childPos);
                        break;
                    } else {
                        // Matching file ID, has children according to path, but is no DF.
                        // Something really bad happened or the path was invalid!
                        throw FileNotFoundException.getInstance();
                    }
                }
            }
        }
        // We could not find the file with that path.
        throw FileNotFoundException.getInstance();
    }

}











