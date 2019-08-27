/**
 * This code is licenced under the GPL version 2.
 */
package pcap.codec.icmp.icmp6;

import pcap.codec.icmp.Icmp;
import pcap.codec.icmp.Icmp6;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public class Icmp6InverseNeighborDiscoveryAdvertisement extends Icmp.IcmpTypeAndCode {

    public static final Icmp6InverseNeighborDiscoveryAdvertisement INVERSE_NEIGHBOR_DISCOVERY_ADVERTISEMENT =
            new Icmp6InverseNeighborDiscoveryAdvertisement((byte) 0, "Inverse Neighbor Discovery Advertisement Message");

    public Icmp6InverseNeighborDiscoveryAdvertisement(Byte code, String name) {
        super((byte) 142, code, name);
    }

    /**
     * Add new {@link Icmp6InverseNeighborDiscoveryAdvertisement} to registry.
     * @param code icmp type code.
     * @param name icmp type name.
     * @return returns {@link Icmp6InverseNeighborDiscoveryAdvertisement}.
     */
    public static Icmp6InverseNeighborDiscoveryAdvertisement register(Byte code, String name) {
        return new Icmp6InverseNeighborDiscoveryAdvertisement(code, name);
    }

    @Override
    public String toString() {
        return super.toString();
    }

    static {
        Icmp6.ICMP6_REGISTRY.add(INVERSE_NEIGHBOR_DISCOVERY_ADVERTISEMENT);
    }

}
