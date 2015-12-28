package org.opennms.protocols.icmp6;

public enum ICMPv6Type {
    DestinationUnreachable(1),
    TimeExceeded(3),
    EchoRequest(128),
    EchoReply(129),

    // this is used to represent a type code that we have not handled
    Other(-1);

    private int m_code;
    private ICMPv6Type(int code) {
        m_code = code;
    }

    public int getCode() {
        return m_code;
    }

    public static ICMPv6Type toType(byte typeCode) {
        int code = (typeCode & 0xff);
        for(ICMPv6Type p : ICMPv6Type.values()) {
            if (code == p.getCode()) {
                return p;
            }
        }
        return Other;
    }
}
