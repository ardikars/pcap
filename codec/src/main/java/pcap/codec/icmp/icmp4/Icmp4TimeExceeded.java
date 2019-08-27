/**
 * This code is licenced under the GPL version 2.
 */
package pcap.codec.icmp.icmp4;

import pcap.codec.icmp.Icmp;
import pcap.codec.icmp.Icmp4;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public class Icmp4TimeExceeded extends Icmp.IcmpTypeAndCode {

    public static final Icmp4TimeExceeded TTL_EXPIRED_IN_TRANSIT =
            new Icmp4TimeExceeded((byte) 0, "TTL expired in transit");

    public static final Icmp4TimeExceeded FRAGMENT_REASSEMBLY_TIME_EXEEDED =
            new Icmp4TimeExceeded((byte) 1, "Fragment reassembly time exceeded");

    public Icmp4TimeExceeded(Byte code, String name) {
        super((byte) 11, code, name);
    }

    /**
     * Add new {@link Icmp4TimeExceeded} to registry.
     * @param code icmp type code.
     * @param name icmp type name.
     * @return returns {@link Icmp4TimeExceeded}.
     */
    public static Icmp4TimeExceeded register(Byte code, String name) {
        return new Icmp4TimeExceeded(code, name);
    }

    @Override
    public String toString() {
        return super.toString();
    }

    static {
        Icmp4.ICMP4_REGISTRY.add(TTL_EXPIRED_IN_TRANSIT);
        Icmp4.ICMP4_REGISTRY.add(FRAGMENT_REASSEMBLY_TIME_EXEEDED);
    }

}
