package org.opennms.protocols.icmp4;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

import org.opennms.protocols.icmp.ICMPSocket;
import org.opennms.protocols.icmp.ResponsePacket;

public class ICMPv4Socket extends ICMPSocket {
    public ICMPv4Socket(int pingerId) throws IOException {
        super(pingerId, false);
    }

    @Override
    public Inet4Address getLocalhost() throws UnknownHostException {
        return (Inet4Address)InetAddress.getByName("127.0.0.1");
    }

    @Override
    public ICMPv4EchoReply buildEchoReply(ResponsePacket packet) {
        return new ICMPv4EchoReply(packet);
    }
}
