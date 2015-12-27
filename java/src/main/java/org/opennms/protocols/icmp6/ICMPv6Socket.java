package org.opennms.protocols.icmp6;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

import org.opennms.protocols.icmp.ICMPSocket;

public class ICMPv6Socket extends ICMPSocket {
    public ICMPv6Socket(int pingerId) throws IOException {
        super(pingerId, true);
    }

    @Override
    public Inet6Address getLocalhost() throws UnknownHostException {
        return (Inet6Address)InetAddress.getByName("::1");
    }

    @Override
    public ICMPv6EchoReply buildEchoReply(DatagramPacket packet) {
        return new ICMPv6EchoReply(packet);
    }
}
