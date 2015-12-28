package org.opennms.protocols.icmp4;

import java.net.InetAddress;

import org.opennms.protocols.icmp.ICMPEchoReply;
import org.opennms.protocols.icmp.ResponsePacket;

public class ICMPv4EchoReply extends ICMPv4EchoPacket implements ICMPEchoReply {

    private final InetAddress m_source;

    public ICMPv4EchoReply(ResponsePacket packet) {
        super(packet.getData());
        m_source = packet.getSource();
        setReceivedTime(packet.getReceivedTime());
        setPingRTT(getReceivedTime() - getSentTime());
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
