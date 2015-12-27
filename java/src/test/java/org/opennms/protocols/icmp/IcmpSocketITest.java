/*******************************************************************************
 * This file is part of OpenNMS(R).
 *
 * Copyright (C) 2015 The OpenNMS Group, Inc.
 * OpenNMS(R) is Copyright (C) 1999-2015 The OpenNMS Group, Inc.
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

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.opennms.protocols.icmp4.ICMPv4Socket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
    private static final Logger LOG = LoggerFactory.getLogger(IcmpSocketITest.class);

    @BeforeClass
    public static void setUpClass() {
        Path library = Paths.get(System.getProperty("user.dir"), "..", "dist", "libjicmp2.so");
        System.setProperty("opennms.library.jicmp2", library.toString());
    }

    @Test
    public void canPingLocalhostUsingIPv4Address() throws Exception {
        final InetAddress target = InetAddress.getByName("127.0.0.1");
        ICMPEchoReply responsePacket = pingIt(target);
        System.out.println("IPv4 RTT: " + responsePacket.getRoundTripTime());
        assertTrue(responsePacket.getPacketSize() > 1);
    }

    @Ignore
    @Test
    public void canPingLocalhostUsingIPv6Address() throws Exception {
        final InetAddress target = InetAddress.getByName("::1");
        ICMPEchoReply responsePacket = pingIt(target);
        System.out.println("IPv6 RTT: " + responsePacket.getRoundTripTime());
        assertTrue(responsePacket.getPacketSize() > 1);
    }

    private static ICMPEchoReply pingIt(InetAddress target) throws IOException {
        try (ICMPv4Socket socket = new ICMPv4Socket(1)) {
            ICMPEchoRequest req = new ICMPEchoRequestBuilder(target)
                    .withThreadId(1)
                    .withPacketSize(60)
                    .withIdentity((short)1)
                    .withSequenceId(1)
                    .build();
            LOG.info("Sending echo request to '{}': {}", target, req);
            socket.send(req);
            LOG.info("Waiting for echo response...");
            return socket.receive();
        }
    }
}
