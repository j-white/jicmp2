package org.opennms.protocols.icmp4;

import java.net.DatagramPacket;
import java.net.InetAddress;

import org.opennms.protocols.icmp.ICMPEchoRequest;

public class ICMPv4EchoRequest extends ICMPv4EchoPacket implements ICMPEchoRequest {

    private final InetAddress m_target;

    public ICMPv4EchoRequest(InetAddress target, long tid, int packetsize) {
        super(tid, packetsize);
        m_target = target;
    }

    @Override
    public InetAddress getDestination() {
        return m_target;
    }
 
    @Override
    public DatagramPacket toDatagram() {
        final byte[] requestData = toBytes();
        return new DatagramPacket(requestData, requestData.length, m_target, 0);
    }
}
