package org.opennms.protocols.icmp4;

import java.net.DatagramPacket;
import java.net.InetAddress;

import org.opennms.protocols.icmp.ICMPEchoReply;

public class ICMPv4EchoReply extends ICMPv4EchoPacket implements ICMPEchoReply {

    public ICMPv4EchoReply(long tid) {
        super(tid);
    }

    public ICMPv4EchoReply(DatagramPacket packet) {
        super(0);
    }

    @Override
    public InetAddress getSource() {
        return null;
    }

    @Override
    public long getRoundTripTime() {
        return 0;
    }

}
