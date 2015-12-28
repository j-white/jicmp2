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

import java.io.FileDescriptor;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Native interface used to support both ICMPv4 and ICMPv6 sockets.
 */
public abstract class ICMPSocket implements AutoCloseable {

    private static final Logger LOG = LoggerFactory.getLogger(ICMPSocket.class);
    
    private static final String LIBRARY_NAME = "jicmp2";
    private static final String PROPERTY_NAME = "opennms.library.jicmp2";

    /**
     * This instance is used by the native code to save and store file
     * descriptor information about the underlying socket.
     * 
     * This needs to be constructed prior to calling the init method.
     */
    private final FileDescriptor m_rawFd;

    /**
     * This instance is used by the native code to store a reference
     * to the receive buffer, which is used by the receivePacket() call.
     */
    private long m_receiveBufferPtr = 0L;

    private final int m_pingerId;

    private final boolean m_useIPv6;

    /**
     * Constructs a new socket that is able to send and receive ICMP messages.
     * The newly constructed socket will receive all ICMP messages directed at
     * the local machine. The application must be prepared to handle any and
     * discard any non-interesting ICMP messages.
     * 
     * @exception java.io.IOException
     *                This exception is thrown if the socket fails to be opened
     *                correctly.
     */
    public ICMPSocket(int pingerId, boolean useIPv6) throws IOException {
        String property = System.getProperty(PROPERTY_NAME);
        if (property != null) {
            LOG.debug("System property '{}' set to '{}'  Attempting to load {} library from this location.",
                    PROPERTY_NAME, property, LIBRARY_NAME);
            System.load(property);
        } else {
            LOG.debug("System property '{}' not set.  Attempting to load library using System.loadLibrary(\"{}\").",
                    PROPERTY_NAME, LIBRARY_NAME);
            System.loadLibrary(LIBRARY_NAME);
        }
        LOG.info("Successfully loaded {} library.", LIBRARY_NAME);

        m_pingerId = pingerId;
        m_useIPv6 = useIPv6;
        m_rawFd = new FileDescriptor();
        initSocket();

        String osName = System.getProperty("os.name");
        if (osName != null && osName.toLowerCase().startsWith("windows")) {
            // Windows complains if you receive before sending a packet
	        send(new ICMPEchoRequestBuilder(getLocalhost()).build());
        }
    }

    public abstract InetAddress getLocalhost() throws UnknownHostException;

    public abstract ICMPEchoReply buildEchoReply(ResponsePacket packet);

    public void send(ICMPEchoRequest request) throws IOException {
        sendPacket(request.getDestination(), request.toBytes());
    }

    public ICMPEchoReply receive() throws IOException {
        return buildEchoReply(receivePacket());
    }

    /**
     * This method is used to open the initial operating system icmp socket. The
     * descriptor for the socket is stored in the member m_rawFd.
     * 
     * @throws java.io.IOException
     *             This is thrown if an error occurs opening the ICMP socket.
     */
    private final native void initSocket() throws IOException;

    /**
     * This method is used to send the passed datagram using the ICMP transport.
     * The destination of the datagram packet is used as the send to destination
     * for the underlying ICMP socket. The port number of the datagram packet is
     * ignored completely.
     * 
     * @exception java.io.IOException
     *                Thrown if an error occurs sending the datagram to the
     *                remote host.
     * @exception java.net.NoRouteToHostException
     *                Thrown if the destination address is a broadcast address.
     */
    private final native void sendPacket(InetAddress target, byte[] data) throws IOException;

    /**
     * This method is used to receive the next ICMP datagram from the operating
     * system. The returned datagram packet's address is set to the sending
     * host's address. The port number is always set to Zero, and the buffer is
     * set to the contents of the raw ICMP message.
     * 
     * @exception java.io.IOException
     *                Thrown if an error occurs reading the next ICMP message.
     * 
     */
    private final native ResponsePacket receivePacket() throws IOException;

    /**
     * This method is used to close and release the resources associated with the
     * instance. The file descriptor is closed at the operating system level and
     * any subsequent calls to this instance should result in exceptions being
     * generated.
     */
    public final native void close();
}
