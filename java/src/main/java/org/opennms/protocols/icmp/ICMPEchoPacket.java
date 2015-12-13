package org.opennms.protocols.icmp;

import java.net.DatagramPacket;
import java.net.InetAddress;

public interface ICMPEchoPacket {

    /**
     * Converts the object into an array of bytes which is suitable for
     * transmission to remote hosts.
     * 
     * @return The object as an array of bytes.
     */
    public byte[] toBytes();
    
    public DatagramPacket toDatagram(InetAddress target);
}
