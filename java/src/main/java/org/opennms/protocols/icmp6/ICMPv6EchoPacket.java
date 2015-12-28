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

import java.net.DatagramPacket;
import java.nio.ByteBuffer;

import org.opennms.protocols.icmp.ICMPEchoPacket;

/**
 * ICMPEchoReply
 *
 * @author brozow
 */
public class ICMPv6EchoPacket extends ICMPv6Packet implements ICMPEchoPacket {

    // This long is equivalent to 'OpenNMS!' in ascii
    public static final long COOKIE = 0x4F70656E4E4D5321L;
    
    // Offsets for TYPE, CODE and CHECK_SUM defined in ICMPv6Packet
    public static final int HEADER_OFFSET_IDENTIFIER = 4;
    public static final int HEADER_OFFSET_SEQUENCE_NUMBER = 6;
    public static final int HEADER_LENGTH = 8;

    // Packet payload format
    public static final int DATA_OFFSET_SENTTIME = 0;
    public static final int DATA_OFFSET_THREAD_ID = 8;
    public static final int DATA_OFFSET_COOKIE = 16;
    public static final int DATA_LENGTH = 8*5;

    private final ByteBuffer m_dataBuffer;

    public ICMPv6EchoPacket(int size) {
        super(size);
        ByteBuffer content = m_packetData.duplicate();
        content.position(HEADER_LENGTH);
        m_dataBuffer = content.slice();
    }

    public ICMPv6EchoPacket(ICMPv6Packet icmpPacket) {
        super(icmpPacket);
        ByteBuffer content = m_packetData.duplicate();
        content.position(HEADER_LENGTH);
        m_dataBuffer = content.slice();
    }

    public ICMPv6EchoPacket(byte[] bytes) {
        this(new ICMPv6Packet(bytes, 0, bytes.length));
    }

    public ByteBuffer getDataBuffer() {
        return m_dataBuffer;
    }
    
    public int getIdentifier() {
        return getUnsignedShort(HEADER_OFFSET_IDENTIFIER);
    }
    
    public void setIdentifier(int id) {
        setUnsignedShort(HEADER_OFFSET_IDENTIFIER, id);
    }
    
    public int getSequenceNumber() {
        return getUnsignedShort(HEADER_OFFSET_SEQUENCE_NUMBER);
    }
    
    public void setSequenceNumber(int sn) {
        setUnsignedShort(HEADER_OFFSET_SEQUENCE_NUMBER, sn);
    }
    
    public long getSentTime() {
        return getDataBuffer().getLong(DATA_OFFSET_SENTTIME);
    }
    
    public void setSentTime(long sentTime) {
        getDataBuffer().putLong(DATA_OFFSET_SENTTIME, sentTime);
    }

    @Override
    public long getThreadId() {
        return getDataBuffer().getLong(DATA_OFFSET_THREAD_ID);
    }
    
    public void setThreadId(long threadId) {
        getDataBuffer().putLong(DATA_OFFSET_THREAD_ID, threadId);
    }

    public long getCookie() {
        return getDataBuffer().getLong(DATA_OFFSET_COOKIE);
    }
    public void setCookie() {
        getDataBuffer().putLong(DATA_OFFSET_COOKIE, COOKIE);
    }

    @Override
    public DatagramPacket toDatagram() {
        final byte[] requestData = toBytes();
        return new DatagramPacket(requestData, requestData.length, null, 0);
    }

    @Override
    public short getIdentity() {
        return (short)getIdentifier();
    }

    @Override
    public short getSequenceId() {
        return (short)getSequenceNumber();
    }
}
