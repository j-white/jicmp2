package org.opennms.protocols.icmp;

import java.io.FileDescriptor;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;

import org.opennms.protocols.icmp4.ICMPv4EchoPacket;
import org.opennms.protocols.icmp6.ICMPv6EchoRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ICMPSocket implements AutoCloseable {

    private static final Logger LOG = LoggerFactory.getLogger(ICMPSocket.class);
    
    private static final String LIBRARY_NAME = "jicmp2";
    private static final String PROPERTY_NAME = "opennms.library.jicmp2";
    private static final String LOGGER_PROPERTY_NAME = "opennms.logger.jicmp";
    
    /**
     * This instance is used by the native code to save and store file
     * descriptor information about the icmp socket. This needs to be
     * constructed prior to calling the init method, preferable in the
     * constructor.
     * 
     * It looks unused, but it is used solely by native code.
     */
    private final FileDescriptor m_rawFd;

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
            LOG.debug("System property '" + PROPERTY_NAME + "' set to '" + System.getProperty(PROPERTY_NAME) + ".  Attempting to load " + LIBRARY_NAME + " library from this location.");
            System.load(property);
        } else {
            LOG.debug("System property '" + PROPERTY_NAME + "' not set.  Attempting to load library using System.loadLibrary(\"" + LIBRARY_NAME + "\").");
            System.loadLibrary(LIBRARY_NAME);
        }
        LOG.info("Successfully loaded " + LIBRARY_NAME + " library.");

        m_pingerId = pingerId;
        m_useIPv6 = useIPv6;
        m_rawFd = new FileDescriptor();
        initSocket();

        String osName = System.getProperty("os.name");
        if (osName != null && osName.toLowerCase().startsWith("windows")) {
            // Windows complains if you receive before sending a packet
            ICMPEchoPacket p;
            InetAddress addr;
            if (m_useIPv6) {
                addr = InetAddress.getByName("::1");
                p = new ICMPv6EchoRequest(1, 1, 1);
            } else {
                addr = InetAddress.getByName("127.0.0.1");
                ICMPv4EchoPacket v4p = new ICMPv4EchoPacket(0);
                v4p.setIdentity((short) 0);
                v4p.computeChecksum();
                p = v4p;
            }
	        send(p.toDatagram(addr));
        }
    }

    /**
     * This method is used to open the initial operating system icmp socket. The
     * descriptor for the socket is stored in the member m_rawFd.
     * 
     * @throws java.io.IOException
     *             This is thrown if an error occurs opening the ICMP socket.
     */
    private native void initSocket() throws IOException;

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
    public final native void send(DatagramPacket packet) throws IOException;

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
    public final native DatagramPacket receive() throws IOException;

    /**
     * This method is used to close and release the resources associated with the
     * instance. The file descriptor is closed at the operating system level and
     * any subsequent calls to this instance should result in exceptions being
     * generated.
     */
    public final native void close();
}
