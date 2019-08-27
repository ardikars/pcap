/**
 * This code is licenced under the GPL version 2.
 */
package pcap.codec.icmp.icmp6;

import pcap.codec.icmp.Icmp;
import pcap.codec.icmp.Icmp6;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public class Icmp6MobilePrefixAdvertisement extends Icmp.IcmpTypeAndCode {

    public static final Icmp6MobilePrefixAdvertisement MOBILE_PREFIX_ADVERTISEMENT =
            new Icmp6MobilePrefixAdvertisement((byte) 0, "Mobile Prefix Advertisement");

    public Icmp6MobilePrefixAdvertisement(Byte code, String name) {
        super((byte) 147, code, name);
    }

    /**
     * Add new {@link Icmp6MobilePrefixAdvertisement} to registry.
     * @param code icmp type code.
     * @param name icmp type name.
     * @return returns {@link Icmp6MobilePrefixAdvertisement}.
     */
    public static Icmp6MobilePrefixAdvertisement register(Byte code, String name) {
        return new Icmp6MobilePrefixAdvertisement(code, name);
    }

    @Override
    public String toString() {
        return super.toString();
    }

    static {
        Icmp6.ICMP6_REGISTRY.add(MOBILE_PREFIX_ADVERTISEMENT);
    }

}
