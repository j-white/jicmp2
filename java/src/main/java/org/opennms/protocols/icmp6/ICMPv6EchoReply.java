package org.opennms.protocols.icmp6;

import java.net.DatagramPacket;
import java.net.InetAddress;

import org.opennms.protocols.icmp.ICMPEchoReply;

public class ICMPv6EchoReply extends ICMPv6EchoPacket implements ICMPEchoReply {

    public ICMPv6EchoReply(int size) {
        super(size);
        // TODO Auto-generated constructor stub
    }

    public ICMPv6EchoReply(DatagramPacket packet) {
        super(64);
        // TODO Auto-generated constructor stub
    }

    @Override
    public InetAddress getSource() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public long getReceivedTime() {
        // TODO Auto-generated method stub
        return 0;
    }

}
