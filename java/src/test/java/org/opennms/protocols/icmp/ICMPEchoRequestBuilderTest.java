package org.opennms.protocols.icmp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.junit.Test;
import org.opennms.protocols.icmp4.ICMPv4EchoRequest;
import org.opennms.protocols.icmp6.ICMPv6EchoRequest;

public class ICMPEchoRequestBuilderTest {

    @Test
    public void canBuildV4Request() throws UnknownHostException {
        InetAddress target = InetAddress.getByName("127.0.0.1");
        ICMPEchoRequest req = new ICMPEchoRequestBuilder(target)
                .withThreadId(42)
                .withIdentity((short) 43)
                .withSequenceId(44)
                .withPacketSize(128)
                .build();
        assertTrue(req instanceof ICMPv4EchoRequest);
        assertEquals(42, req.getThreadId());
        assertEquals(43, req.getIdentity());
        assertEquals(44, req.getSequenceId());
        //assertEquals(128, req.getPacketSize());
        assertEquals(target, req.getDestination());

        assertEquals(target, req.getDestination());
        //assertEquals(128, req.toBytes().length);
    }

    @Test
    public void canBuildV6Request() throws UnknownHostException {
        InetAddress target = InetAddress.getByName("::1");
        ICMPEchoRequest req = new ICMPEchoRequestBuilder(target)
                .withThreadId(42)
                .withIdentity((short) 43)
                .withSequenceId(44)
                .withPacketSize(128)
                .build();
        assertTrue(req instanceof ICMPv6EchoRequest);
        assertEquals(42, req.getThreadId());
        assertEquals(43, req.getIdentity());
        assertEquals(44, req.getSequenceId());
        assertEquals(128, req.getPacketSize());
        assertEquals(target, req.getDestination());

        assertEquals(target, req.getDestination());
        assertEquals(128, req.toBytes().length);
    }
}
