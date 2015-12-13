package org.opennms.protocols.icmp4;

import java.io.IOException;

import org.opennms.protocols.icmp.ICMPSocket;

public class ICMPv4Socket extends ICMPSocket {
    public ICMPv4Socket(int pingerId) throws IOException {
        super(pingerId, false);
    }
}
