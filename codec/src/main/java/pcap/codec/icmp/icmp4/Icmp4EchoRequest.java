/**
 * This code is licenced under the GPL version 2.
 */
package pcap.codec.icmp.icmp4;

import pcap.codec.icmp.Icmp;
import pcap.codec.icmp.Icmp4;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public class Icmp4EchoRequest extends Icmp.IcmpTypeAndCode {

    public static final Icmp4EchoRequest ECHO_REQUEST =
            new Icmp4EchoRequest((byte) 0, "Echo request (used to ping)");

    public Icmp4EchoRequest(Byte code, String name) {
        super((byte) 8, code, name);
    }

    /**
     * Add new {@link Icmp4EchoRequest} to registry.
     * @param code icmp type code.
     * @param name icmp type name.
     * @return returns {@link Icmp4EchoRequest}.
     */
    public static Icmp4EchoRequest register(Byte code, String name) {
        return new Icmp4EchoRequest(code, name);
    }

    @Override
    public String toString() {
        return super.toString();
    }

    static {
        Icmp4.ICMP4_REGISTRY.add(ECHO_REQUEST);
    }

}
