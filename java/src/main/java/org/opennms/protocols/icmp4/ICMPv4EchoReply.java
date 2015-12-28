package org.opennms.protocols.icmp4;

import java.net.InetAddress;

import org.opennms.protocols.icmp.ICMPEchoReply;
import org.opennms.protocols.icmp.ResponsePacket;

public class ICMPv4EchoReply extends ICMPv4EchoPacket implements ICMPEchoReply {

    private final InetAddress m_source;
    private final long m_receivedTime;
    private final long m_roundTripTime;

    public ICMPv4EchoReply(ResponsePacket packet) {
        super(packet.getData());
        m_source = packet.getSource();
        m_receivedTime = packet.getReceivedTime();
        m_roundTripTime = m_receivedTime - getSentTime();
    }

    @Override
    public InetAddress getSource() {
        return m_source;
    }

    @Override
    public long getReceivedTime() {
        return m_receivedTime;
    }

    @Override
    public long getRoundTripTime() {
        return m_roundTripTime;
    }
}
