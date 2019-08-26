/**
 * This code is licenced under the GPL version 2.
 */
package pcap.codec.icmp.icmp6;

import pcap.codec.icmp.Icmp;
import pcap.codec.icmp.Icmp6;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public class Icmp6MulticastListenerQuery extends Icmp.IcmpTypeAndCode {

    public static final Icmp6MulticastListenerQuery MULTICAST_LISTENER_QUERY =
            new Icmp6MulticastListenerQuery((byte) 0, "Multicast listener query");

    public Icmp6MulticastListenerQuery(Byte code, String name) {
        super((byte) 130, code, name);
    }

    /**
     * Add new {@link Icmp6MulticastListenerQuery} to registry.
     * @param code icmp type code.
     * @param name icmp type name.
     * @return returns {@link Icmp6MulticastListenerQuery}.
     */
    public static Icmp6MulticastListenerQuery register(Byte code, String name) {
        return new Icmp6MulticastListenerQuery(code, name);
    }

    @Override
    public String toString() {
        return super.toString();
    }

    static {
        Icmp6.ICMP6_REGISTRY.add(MULTICAST_LISTENER_QUERY);
    }

}
