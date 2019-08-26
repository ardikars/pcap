package pcap.codec.icmp.icmp6;

import pcap.codec.icmp.Icmp;
import pcap.codec.icmp.Icmp6;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public class Icmp6RouterSolicitation extends Icmp.IcmpTypeAndCode {

    public static final Icmp6RouterSolicitation ROUTER_SOLICITATION =
            new Icmp6RouterSolicitation((byte) 0, "Router solicitation");

    protected Icmp6RouterSolicitation(Byte code, String name) {
        super((byte) 133, code, name);
    }

    /**
     * Add new {@link Icmp6RouterSolicitation} to registry.
     * @param code icmp type code.
     * @param name icmp type name.
     * @return returns {@link Icmp6RouterSolicitation}.
     */
    public static Icmp6RouterSolicitation register(Byte code, String name) {
        return new Icmp6RouterSolicitation(code, name);
    }

    @Override
    public String toString() {
        return super.toString();
    }

    static {
        Icmp6.ICMP6_REGISTRY.add(ROUTER_SOLICITATION);
    }

}
