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

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.Objects;

import org.opennms.protocols.icmp4.ICMPv4EchoRequest;
import org.opennms.protocols.icmp6.ICMPv6EchoRequest;

/**
 * Used to build ICMPv4 or ICMPv6 Echo Requests.
 *
 * @author jwhite
 */
public class ICMPEchoRequestBuilder {

    public static final int MIN_PACKET_SIZE = 24;
    public static final int MAX_PACKET_SIZE = 64512;
    public static final int DEFAULT_PACKET_SIZE = 56;

    private final InetAddress m_destination;
    private long m_threadId = 0;
    private int m_packetSize = DEFAULT_PACKET_SIZE;
    private short m_identity = 0;
    private int m_sequenceId = 0;

    public ICMPEchoRequestBuilder(InetAddress destination) {
        m_destination = Objects.requireNonNull(destination, "destination cannot be null");
    }

    public ICMPEchoRequestBuilder withThreadId(long threadId) {
        m_threadId = threadId;
        return this;
    }

    public ICMPEchoRequestBuilder withPacketSize(int packetSize) {
        if (packetSize < MIN_PACKET_SIZE) {
            throw new IllegalArgumentException("packet size must be greater or equal to " + MIN_PACKET_SIZE);
        } else if (packetSize > MAX_PACKET_SIZE) {
            throw new IllegalArgumentException("packet size must be smaller or equal to " + MAX_PACKET_SIZE);
        }
        m_packetSize = packetSize;
        return this;
    }

    public ICMPEchoRequestBuilder withIdentity(short identity) {
        m_identity = identity;
        return this;
    }
    
    public ICMPEchoRequestBuilder withSequenceId(int sequenceId) {
        m_sequenceId = sequenceId;
        return this;
    }

    public ICMPEchoRequest build() {
        if (m_destination instanceof Inet4Address) {
            return buildV4Packet();
        } else if (m_destination instanceof Inet6Address) {
            return buildV6Packet();
        } else {
            throw new IllegalArgumentException("Unsupported InetAddress: " + m_destination.getClass());
        }
    }

    private ICMPEchoRequest buildV4Packet() {
        ICMPv4EchoRequest req = new ICMPv4EchoRequest(m_destination, m_threadId, m_packetSize);
        req.setIdentity(m_identity);
        req.setSequenceId((short)m_sequenceId);
        return req;
    }

    private ICMPEchoRequest buildV6Packet() {
        ICMPv6EchoRequest req = new ICMPv6EchoRequest(m_destination, m_packetSize);
        req.setThreadId(m_threadId);
        req.setIdentifier(m_identity);
        req.setSequenceNumber(m_sequenceId);
        return req;
    }
}
