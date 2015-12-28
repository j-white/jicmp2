package org.opennms.protocols.icmp6;

import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

import org.opennms.protocols.icmp.ICMPEchoReply;
import org.opennms.protocols.icmp.ICMPSocket;
import org.opennms.protocols.icmp.ResponsePacket;

public class ICMPv6Socket extends ICMPSocket {
    public ICMPv6Socket(int pingerId) throws IOException {
        super(pingerId, true);
    }

    @Override
    public Inet6Address getLocalhost() throws UnknownHostException {
        return (Inet6Address)InetAddress.getByName("::1");
    }

    @Override
    public ICMPEchoReply buildEchoReply(ResponsePacket packet) {
        return new ICMPv6EchoReply(packet);
    }
}
