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

package org.opennms.protocols.icmp4;

import java.net.DatagramPacket;

import org.opennms.protocols.icmp.ICMPEchoPacket;
import org.opennms.protocols.icmp.PacketUtils;

/**
 * 
 * @author jwhite
 * @author Brian Weaver
 * @author Sowmya
 */
public class ICMPv4EchoPacket extends ICMPv4Packet implements ICMPEchoPacket {

    /**
     * Timestamp when packet was sent
     */
    private long m_sent;

    /**
     * The thread id of the sender. Effective key for the packet.
     */
    private long m_tid; // thread id

    /**
     * Padding used to make the packet conform to the defacto unix ping program
     * (56 bytes) or whatever packetsize is sent in
     */
    private byte[] m_pad;

    /**
     * Converts a byte to a long and wraps the value to avoid sign extension.
     * The method essentially treats the value of 'b' as an 8-bit unsigned value
     * for conversion purposes.
     * 
     * @param b
     *            The byte to convert.
     * 
     * @return The converted long value.
     */
    static private long byteToLong(byte b) {
        long r = (long) b;
        if (r < 0)
            r += 256;
        return r;
    }

    /**
     * Private constructor to disallow default construction of an object.
     * 
     * @exception java.lang.UnsupportedOperationException
     *                Always thrown.
     */
    @SuppressWarnings("unused")
	private ICMPv4EchoPacket() {
        throw new java.lang.UnsupportedOperationException("illegal constructor call");
    }

    /**
     * Creates a new discovery ping packet that can be sent to a remote protocol
     * stack. The ICMP type is set to an Echo Request. The next sequence in the
     * ICMPHeader base class is set and the sent time is set to the current
     * time.
     * 
     * @param tid
     *            The thread id for the packet.
     * 
     * @see java.lang.System#currentTimeMillis
     */
    public ICMPv4EchoPacket(long tid) {
    	this(tid, 64);
    }

    /**
     * Creates a new discovery ping packet that can be sent to a remote protocol
     * stack. The ICMP type is set to an Echo Request. The next sequence in the
     * ICMPHeader base class is set and the sent time is set to the current
     * time.
     * 
     * @param tid
     *            The thread id for the packet.
     * @param packetsize
     *            The pad size in bytes
     * @see java.lang.System#currentTimeMillis
     */
    public ICMPv4EchoPacket(long tid, int packetsize) {
        super(ICMPv4Packet.TYPE_ECHO_REQUEST, (byte) 0);
        setNextSequenceId();

        m_sent = 0;
        m_tid = tid;
        
        if (packetsize < getMinimumNetworkSize()) {
        	throw new IllegalArgumentException("Minimum size for a ICMPEchoPacket is " + getMinimumNetworkSize() + " bytes.");
        }
        
        m_pad = new byte[packetsize - getMinimumNetworkSize()];
        for (int x = 0; x < PacketUtils.NAMED_PAD.length && x < m_pad.length; x++)
            m_pad[x] = PacketUtils.NAMED_PAD[x];
        for (int x = PacketUtils.NAMED_PAD.length; x < m_pad.length; x++)
            m_pad[x] = (byte) 0;

    }


    /**
     * Creates a new discovery ping packet from the passed buffer.
     * 
     * @param buf
     *            The buffer containing a refected ping packet.
     */
    public ICMPv4EchoPacket(byte[] buf) {
        loadFromBuffer(buf, 0);
    }

    /**
     * Returns the time the packet was sent.
     */
    public final long getSentTime() {
        return m_sent;
    }

    /**
     * Sets the sent time to the current time.
     * 
     * @see java.lang.System#currentTimeMillis
     */
    public final long setSentTime() {
        m_sent = System.currentTimeMillis();
        return m_sent;
    }

    /**
     * Sets the sent time to the passed value.
     * 
     * @param time
     *            The new sent time.
     */
    public final void setSentTime(long time) {
        m_sent = time;
    }

    /**
	 * Returns the size of the integer headers in packet 
     */
    public int getDataSize() {
        return (getHeaderSize() + 32);
    }

    /**
     * Returns the size of the integer headers in the packet plus the required 'OpenNMS!' string.
     */
    public int getMinimumNetworkSize() {
        return (getDataSize() + PacketUtils.NAMED_PAD.length);
    }

    @Override
    public int getPacketSize() {
    	return getDataSize() + m_pad.length;
    }

    /**
     * Computes and stores the current checksum based upon the data currently
     * contained in the object.
     */
    public final void computeChecksum() {
        OC16ChecksumProducer summer = new OC16ChecksumProducer();

        super.computeChecksum(summer);
        summer.add(m_sent);
        summer.add(m_tid);

        //
        // do all the elements combining two bytes
        // into a single short.
        //
        int stop = m_pad.length - (m_pad.length % 2);
        for (int i = 0; i < stop; i += 2)
            summer.add(m_pad[i], m_pad[i + 1]);

        //
        // take care of any stray bytes
        //
        if ((m_pad.length % 2) == 1)
            summer.add(m_pad[m_pad.length - 1]);

        //
        // set the checksum in the header
        //
        super.setChecksum(summer.getChecksum());
    }

    /**
     * Returns the currently set Thread ID
     */
    public final long getTID() {
        return m_tid;
    }

    /**
     * Sets the current Thread Id
     */
    public final void setTID(long tid) {
        m_tid = tid;
    }

    /**
     * Loads the data from the passed buffer into the current object. Once
     * loaded the object's values should reflect the contents of the buffer.
     * 
     * @param buf
     *            The buffer to load from
     * @param offset
     *            The offset to begin loading from
     * 
     * @return The offset of the next byte of data that was not used to
     *         initialize this object.
     * 
     * @exception java.lang.IndexOutOfBoundsException
     *                Thrown if there is not enough data contained in the buffer
     *                to sufficent set the state of the object
     * 
     */
    public final int loadFromBuffer(byte[] buf, int offset) {
        if ((buf.length - offset) < getMinimumNetworkSize())
            throw new IndexOutOfBoundsException("Insufficient Data: packet must be at least " + getMinimumNetworkSize() + " bytes long.");

        offset = super.loadFromBuffer(buf, offset);
        if (!isEchoReply() && !isEchoRequest())
            throw new IllegalArgumentException("Invalid type, must be echo request/reply packet");

        m_sent = 0;
        for (int x = 0; x < 8; x++) {
            m_sent <<= 8;
            m_sent |= byteToLong(buf[offset++]);
        }

        m_tid = 0;
        for (int x = 0; x < 8; x++) {
            m_tid <<= 8;
            m_tid |= byteToLong(buf[offset++]);
        }

        // skip over the header and timestamp data
        int remainingBytes = buf.length - getDataSize();
        if (m_pad == null || m_pad.length != remainingBytes) {
        	m_pad = new byte[remainingBytes];
        }

        for (int x = 0; x < m_pad.length; x++) {
            m_pad[x] = buf[offset++];
        }

        return offset;
    }

    /**
     * Writes the objects data out to the specified buffer at the starting
     * offset. If the buffer does not have sufficent data to store the
     * information then an IndexOutOfBoundsException is thrown.
     * 
     * @param buf
     *            The storage buffer.
     * @param offset
     *            The location to start in buf.
     * 
     * @return The new offset after storing to the buffer.
     * 
     * @exception IndexOutOfBoundsException
     *                Thrown if the buffer does not have enough storage space.
     * 
     */
    public final int storeToBuffer(byte[] buf, int offset) {
        if ((buf.length - offset) < getPacketSize()) {
            throw new IndexOutOfBoundsException("Insufficient Buffer Size.  Need at least " + getPacketSize() + " bytes to store packet.");
        }

        offset = super.storeToBuffer(buf, offset);

        long t = m_sent;
        for (int x = 0; x < 8; x++) {
            buf[offset++] = (byte) (t >>> 56);
            t <<= 8;
        }

        t = m_tid;
        for (int x = 0; x < 8; x++) {
            buf[offset++] = (byte) (t >>> 56);
            t <<= 8;
        }

        for (int x = 0; x < m_pad.length; x++) {
            buf[offset++] = m_pad[x];
        }

        return offset;
    }

    /**
     * Converts the object into an array of bytes which is suitable for
     * transmission to remote hosts.
     * 
     * @return The object as an array of bytes.
     */
    @Override
    public byte[] toBytes() {
        byte[] buf = new byte[getPacketSize()];
        storeToBuffer(buf, 0);
        return buf;
    }

    @Override
    public DatagramPacket toDatagram() {
        final byte[] requestData = toBytes();
        return new DatagramPacket(requestData, requestData.length, null, 0);
    }

    @Override
    public long getThreadId() {
        return m_tid;
    }
}
