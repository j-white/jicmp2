/*
 * This file is part of the OpenNMS(R) Application.
 *
 * OpenNMS(R) is Copyright (C) 2011 The OpenNMS Group, Inc.  All rights reserved.
 * OpenNMS(R) is a derivative work, containing both original code, included code and modified
 * code that was published under the GNU General Public License. Copyrights for modified
 * and included code are below.
 *
 * OpenNMS(R) is a registered trademark of The OpenNMS Group, Inc.
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
 * OpenNMS Licensing       <license@opennms.org>
 *     http://www.opennms.org/
 *     http://www.opennms.com/
 */
package org.opennms.protocols.icmp6;

import java.net.DatagramPacket;
import java.net.InetAddress;
import java.nio.ByteBuffer;

import org.opennms.protocols.icmp.ICMPEchoRequest;

/**
 * ICMPEchoRequest
 *
 * @author brozow
 */
public class ICMPv6EchoRequest extends ICMPv6EchoPacket implements ICMPEchoRequest {
 
    public static final int PACKET_LENGTH = 64;

    private final InetAddress m_target;

    public ICMPv6EchoRequest(InetAddress target, int size) {
        super(size);
        setType(ICMPv6Type.EchoRequest);
        setCode(0);
        m_target = target;

        setIdentifier(1);
        setSequenceNumber(1);

        // data fields
        setThreadId(1);
        setCookie();
        // timestamp is set later

        // fill buffer with 'interesting' data
        ByteBuffer buf = getDataBuffer();
        for(int b = DATA_LENGTH; b < buf.limit(); b++) {
            buf.put(b, (byte)b);
        }
    }

    @Override
    public InetAddress getDestination() {
        return m_target;
    }

    @Override
    public DatagramPacket toDatagram() {
        final byte[] requestData = toBytes();
        return new DatagramPacket(requestData, requestData.length, m_target, 0);
    }
}
