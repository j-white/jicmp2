/*
 * This file is part of the OpenNMS(R) Application.
 *
 * OpenNMS(R) is Copyright (C) 2002-2003 The OpenNMS Group, Inc.  All rights reserved.
 * OpenNMS(R) is a derivative work, containing both original code, included code and modified
 * code that was published under the GNU General Public License. Copyrights for modified 
 * and included code are below.
 *
 * OpenNMS(R) is a registered trademark of The OpenNMS Group, Inc.
 *
 * Modifications:
 *
 * 2007 Jul 25: Move 'main' and related code to a Ping class. Make the code
 *              separable from OpenNMS.
 * 2007 Jun 23: Fix warnings on static members and eliminate warning on
 *              m_rawFd that is only used in native code. - dj@opennms.org
 * 2007 May 21: Improve logging of shared library loading. - dj@opennms.org
 * 2003 Mar 05: Changes to support response times and more platforms.
 *
 * Original code base Copyright (C) 1999-2001 Oculan Corp.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * For more information contact:
 *      OpenNMS Licensing       <license@opennms.org>
 *      http://www.opennms.org/
 *      http://www.opennms.com/
 */
package org.opennms.protocols.icmp;

import java.io.IOException;
import java.net.SocketException;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.BeforeClass;
import org.junit.Test;

public class IcmpSocketTest {

    @BeforeClass
    public static void setUpClass() {
        Path library = Paths.get(System.getProperty("user.dir"), "..", "dist", "libjicmp2.so");
        System.setProperty("opennms.library.jicmp2", library.toString());
    }

    @Test
    public void canLoadLibrary() throws IOException {
        try (IcmpSocket socket = new IcmpSocket(1)) {
        } catch (SocketException e) {
            // Socket initialization can fail with (1, Operation not permitted)
            // this means we were at least able to load the library
        }
    }
}
