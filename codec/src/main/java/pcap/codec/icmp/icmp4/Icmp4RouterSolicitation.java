/**
 * This code is licenced under the GPL version 2.
 */
package pcap.codec.icmp.icmp4;

import pcap.codec.icmp.Icmp;
import pcap.codec.icmp.Icmp4;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public class Icmp4RouterSolicitation extends Icmp.IcmpTypeAndCode {

    public static final Icmp4RouterSolicitation ROUTER_DISCOVERY_SELECTION_SOLICITATION =
            new Icmp4RouterSolicitation((byte) 0, "Router discovery/selection/solicitation");

    public Icmp4RouterSolicitation(Byte code, String name) {
        super((byte) 10, code, name);
    }

    /**
     * Add new {@link Icmp4RouterSolicitation} to registry.
     * @param code icmp type code.
     * @param name icmp type name.
     * @return returns {@link Icmp4RouterSolicitation}.
     */
    public static Icmp4RouterSolicitation register(Byte code, String name) {
        return new Icmp4RouterSolicitation(code, name);
    }

    @Override
    public String toString() {
        return super.toString();
    }

    static {
        Icmp4.ICMP4_REGISTRY.add(ROUTER_DISCOVERY_SELECTION_SOLICITATION);
    }

}
