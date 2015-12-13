package org.opennms.protocols.icmp6;

import java.io.IOException;

import org.opennms.protocols.icmp.ICMPSocket;

public class ICMPv6Socket extends ICMPSocket {
    public ICMPv6Socket(int pingerId) throws IOException {
        super(pingerId, true);
    }
}
