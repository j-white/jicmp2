/*******************************************************************************
 * This file is part of OpenNMS(R).
 *
 * Copyright (C) 2016 The OpenNMS Group, Inc.
 * OpenNMS(R) is Copyright (C) 1999-2016 The OpenNMS Group, Inc.
 *
 * OpenNMS(R) is a registered trademark of The OpenNMS Group, Inc.
 *
 * OpenNMS(R) is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
 *
 * OpenNMS(R) is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with OpenNMS(R).  If not, see:
 *      http://www.gnu.org/licenses/
 *
 * For more information contact:
 *     OpenNMS(R) Licensing <license@opennms.org>
 *     http://www.opennms.org/
 *     http://www.opennms.com/
 *******************************************************************************/

package org.opennms.protocols.icmp;

/**
 * Constants and utilities for manipulating the packet bytes.
 *
 * @author jwhite
 */
public class PacketUtils {

    /**
     * Unique named padding that is placed in front of the incremental padding.
     */
    public static final byte NAMED_PAD[] = { (byte) 'O', (byte) 'p', (byte) 'e', (byte) 'n', (byte) 'N', (byte) 'M', (byte) 'S', (byte) '!' };


    /**
     * Converts a byte to a short.
     * 
     * @param b
     *            The byte to convert.
     * 
     * @return The converted byte.
     * 
     */
    public static short byteToShort(byte b) {
        short s = (short) b;
        if (s < 0)
            s += 256;
        return s;
    }
}
