package pcap.codec.icmp.icmp6;

import pcap.codec.icmp.Icmp;
import pcap.codec.icmp.Icmp6;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public class Icmp6NeighborSolicitation extends Icmp.IcmpTypeAndCode {

    public static final Icmp6NeighborSolicitation NEIGHBOR_SOLICITATION =
            new Icmp6NeighborSolicitation((byte) 0, "Neighbor solicitation");

    public Icmp6NeighborSolicitation(Byte code, String name) {
        super((byte) 135, code, name);
    }

    /**
     * Add new {@link Icmp6NeighborSolicitation} to registry.
     * @param code icmp type code.
     * @param name icmp type name.
     * @return returns {@link Icmp6NeighborSolicitation}.
     */
    public static Icmp6NeighborSolicitation register(Byte code, String name) {
        return new Icmp6NeighborSolicitation(code, name);
    }

    @Override
    public String toString() {
        return super.toString();
    }

    static {
        Icmp6.ICMP6_REGISTRY.add(NEIGHBOR_SOLICITATION);
    }

}
