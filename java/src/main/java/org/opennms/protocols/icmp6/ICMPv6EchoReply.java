package org.opennms.protocols.icmp6;

import java.net.InetAddress;

import org.opennms.protocols.icmp.ICMPEchoReply;
import org.opennms.protocols.icmp.ResponsePacket;

public class ICMPv6EchoReply extends ICMPv6EchoPacket implements ICMPEchoReply {

    private final InetAddress m_source;

    public ICMPv6EchoReply(ResponsePacket packet) {
        super(packet.getData());
        m_source = packet.getSource();
        setReceiveTime(packet.getReceivedTime());
        setRoundTripTime(getReceivedTime() - getSentTime());
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
