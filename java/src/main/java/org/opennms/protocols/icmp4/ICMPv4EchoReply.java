package org.opennms.protocols.icmp4;

import java.net.DatagramPacket;
import java.net.InetAddress;

import org.opennms.protocols.icmp.ICMPEchoReply;

public class ICMPv4EchoReply extends ICMPv4EchoPacket implements ICMPEchoReply {

    private final InetAddress m_source;

    public ICMPv4EchoReply(DatagramPacket packet) {
        super(packet.getData());
        m_source = packet.getAddress();
    }

    @Override
    public InetAddress getSource() {
        return m_source;
    }

    @Override
    public long getRoundTripTime() {
        return getPingRTT();
    }
}
