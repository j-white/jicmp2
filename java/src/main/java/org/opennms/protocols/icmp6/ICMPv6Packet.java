/*
 * This file is part of the OpenNMS(R) Application.
 *
 * OpenNMS(R) is Copyright (C) 2010 The OpenNMS Group, Inc.  All rights reserved.
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

import java.nio.ByteBuffer;

/**
 * ICMPPacket
 *
 * @author brozow
 */
public class ICMPv6Packet {
    
    public static final int CHECKSUM_INDEX = 2;
    public static final int HEADER_OFFSET_TYPE = 0;
    public static final int HEADER_OFFSET_CODE = 1;
    public static final int HEADER_OFFSET_CHECKSUM = 2;

    ByteBuffer m_packetData;

    public ICMPv6Packet(byte[] bytes, int offset, int length) {
        this(ByteBuffer.wrap(bytes, offset, length));
    }

    public ICMPv6Packet(ByteBuffer ipPayload) {
        m_packetData = ipPayload;
    }
    
    public ICMPv6Packet(ICMPv6Packet icmpPacket) {
        this(icmpPacket.m_packetData.duplicate());
    }
    
    public ICMPv6Packet(int size) {
        this(ByteBuffer.allocate(size));
    }
    
    public int getPacketSize() {
        return m_packetData.limit();
    }

    public ICMPv6Type getAType() {
        return ICMPv6Type.toType(m_packetData.get(HEADER_OFFSET_TYPE));
    }

    public void setType(ICMPv6Type t) {
        m_packetData.put(HEADER_OFFSET_TYPE, ((byte)(t.getCode())));
    }

    public int getCode() {
        return 0xff & m_packetData.get(HEADER_OFFSET_CODE);
    }

    public void setCode(int code) {
        m_packetData.put(HEADER_OFFSET_CODE, ((byte)code));
    }

    public int getChecksum() {
        return getUnsignedShort(HEADER_OFFSET_CHECKSUM);
    }
    
    public void setBytes(int index, byte[] b) {
        ByteBuffer payload = m_packetData;
        int oldPos = payload.position();
        try {
            payload.position(index);
            payload.put(b);
        } finally {
            payload.position(oldPos);
        }
    }

    public int getUnsignedShort(int index) {
        return m_packetData.getShort(index) & 0xffff;
    }

    public void setUnsignedShort(int index, int us) {
        m_packetData.putShort(index, ((short)(us & 0xffff)));
    }

    public byte[] toBytes() {
        return m_packetData.array();
    }
}
