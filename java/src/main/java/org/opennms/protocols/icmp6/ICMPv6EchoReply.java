package org.opennms.protocols.icmp6;

import java.net.DatagramPacket;
import java.net.InetAddress;

import org.opennms.protocols.icmp.ICMPEchoReply;

public class ICMPv6EchoReply extends ICMPv6EchoPacket implements ICMPEchoReply {

    private final InetAddress m_source;

    public ICMPv6EchoReply(DatagramPacket packet) {
        super(packet.getData());
        m_source = packet.getAddress();
    }

    @Override
    public InetAddress getSource() {
        return m_source;
    }

    @Override
    public long getReceivedTime() {
        return this.getReceiveTime();
    }
}
