package org.opennms.protocols.icmp4;

import java.net.InetAddress;

import org.opennms.protocols.icmp.ICMPEchoRequest;

public class ICMPv4EchoRequest extends ICMPv4EchoPacket implements ICMPEchoRequest {

    public ICMPv4EchoRequest(long tid, int packetsize) {
        super(tid, packetsize);
    }

    @Override
    public InetAddress getDestination() {
        // TODO Auto-generated method stub
        return null;
    }

}
