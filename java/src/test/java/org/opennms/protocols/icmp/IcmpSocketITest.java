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

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.BeforeClass;
import org.junit.Test;
import org.opennms.protocols.icmp4.ICMPv4EchoPacket;
import org.opennms.protocols.icmp4.ICMPv4Socket;
import org.opennms.protocols.icmp6.ICMPv6EchoReply;
import org.opennms.protocols.icmp6.ICMPv6EchoRequest;
import org.opennms.protocols.icmp6.ICMPv6Packet;
import org.opennms.protocols.icmp6.ICMPv6Socket;

/**
 *
 * See https://lkml.org/lkml/2011/5/18/305 for running as non-root
 * 
 * [RFC v2] ICMP sockets: https://lwn.net/Articles/422330/
 *
 * sudo sysctl -w net.ipv4.ping_group_range="0 429496729"
 *
 * @author jwhite
 */
public class IcmpSocketITest {

    @BeforeClass
    public static void setUpClass() {
        Path library = Paths.get(System.getProperty("user.dir"), "..", "dist", "libjicmp2.so");
        System.setProperty("opennms.library.jicmp2", library.toString());
    }

    @Test
    public void canPingLocalhostUsingIPv4Address() throws Exception {
        final InetAddress target = InetAddress.getByName("127.0.0.1");
        ICMPv4EchoPacket responsePacket = pingIt(target);
        System.out.println("IPv4 RTT: " + responsePacket.getPingRTT());
        assertTrue(responsePacket.getPacketSize() > 1);
    }

    @Test
    public void canPingLocalhostUsingIPv6Address() throws Exception {
        final InetAddress target = InetAddress.getByName("::1");
        ICMPv6EchoReply responsePacket = pingIt6(target);
        System.out.println("IPv6 RTT: " + responsePacket.getRoundTripTime());
        assertTrue(responsePacket.getPacketLength() > 1);
    }

    private static ICMPv4EchoPacket pingIt(InetAddress target) throws IOException {
        try (ICMPv4Socket socket = new ICMPv4Socket(1)) {
            ICMPv4EchoPacket requestPacket = new ICMPv4EchoPacket(1, 60);
            requestPacket.setIdentity((short)1);
            requestPacket.setSequenceId((short)1);
            requestPacket.computeChecksum();

            socket.send(requestPacket.toDatagram(target));

            DatagramPacket responseData = socket.receive();
            return new ICMPv4EchoPacket(responseData.getData());
        }
    }

    private static ICMPv6EchoReply pingIt6(InetAddress target) throws IOException {
        try (ICMPv6Socket socket = new ICMPv6Socket(1)) {
            ICMPv6EchoRequest requestPacket = new ICMPv6EchoRequest(1, 1, 1);

            socket.send(requestPacket.toDatagram(target));

            DatagramPacket responseData = socket.receive();
            byte[] bytes = responseData.getData();
            return new ICMPv6EchoReply(new ICMPv6Packet(bytes, 0, bytes.length));
        }
    }
}
