package pcap.codec.icmp.icmp4;

import pcap.codec.icmp.Icmp;
import pcap.codec.icmp.Icmp4;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public class Icmp4EchoReply extends Icmp.IcmpTypeAndCode {

    public static final Icmp4EchoReply ECHO_REPLY =
            new Icmp4EchoReply((byte) 0, "Echo reply (used to ping)");

    public Icmp4EchoReply(Byte code, String name) {
        super((byte) 0, code, name);
    }

    /**
     * Add new {@link Icmp4EchoRequest} to registry.
     * @param code icmp type code.
     * @param name icmp type name.
     * @return returns {@link Icmp4EchoRequest}.
     */
    public static Icmp4EchoReply register(Byte code, String name) {
        return new Icmp4EchoReply(code, name);
    }

    @Override
    public String toString() {
        return super.toString();
    }

    static {
        Icmp4.ICMP4_REGISTRY.add(ECHO_REPLY);
    }

}
