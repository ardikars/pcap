/**
 * This code is licenced under the GPL version 2.
 */
package pcap.codec.icmp.icmp6;

import pcap.codec.icmp.Icmp;
import pcap.codec.icmp.Icmp6;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public class Icmp6MulticastListenerReportV2 extends Icmp.IcmpTypeAndCode {

    public static final Icmp6MulticastListenerReportV2 MULTICAST_LISTENER_REPORT =
            new Icmp6MulticastListenerReportV2((byte) 0, "Multicast listener report");

    public Icmp6MulticastListenerReportV2(Byte code, String name) {
        super((byte) 143, code, name);
    }

    /**
     * Add new {@link Icmp6MulticastListenerReportV2} to registry.
     * @param code icmp type code.
     * @param name icmp type name.
     * @return returns {@link Icmp6MulticastListenerReportV2}.
     */
    public static Icmp6MulticastListenerReportV2 register(Byte code, String name) {
        return new Icmp6MulticastListenerReportV2(code, name);
    }

    @Override
    public String toString() {
        return super.toString();
    }

    static {
        Icmp6.ICMP6_REGISTRY.add(MULTICAST_LISTENER_REPORT);
    }

}
