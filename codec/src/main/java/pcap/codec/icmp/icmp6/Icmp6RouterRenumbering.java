package pcap.codec.icmp.icmp6;

import pcap.codec.icmp.Icmp;
import pcap.codec.icmp.Icmp6;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public class Icmp6RouterRenumbering extends Icmp.IcmpTypeAndCode {

    public static final Icmp6RouterRenumbering ROUTER_RENUMBERING_COMMAND =
            new Icmp6RouterRenumbering((byte) 0, "Router renumbering command");

    public static final Icmp6RouterRenumbering ROUTER_RENUMBERING_RESULT =
            new Icmp6RouterRenumbering((byte) 1, "Router renumbering result");

    public static final Icmp6RouterRenumbering SEQUENCE_NUMBER_RESET =
            new Icmp6RouterRenumbering((byte) 255, "Sequence number reset");

    public Icmp6RouterRenumbering(Byte code, String name) {
        super((byte) 138, code, name);
    }

    /**
     * Add new {@link Icmp6RouterRenumbering} to registry.
     * @param code icmp type code.
     * @param name icmp type name.
     * @return returns {@link Icmp6RouterRenumbering}.
     */
    public static Icmp6RouterRenumbering register(Byte code, String name) {
        return new Icmp6RouterRenumbering(code, name);
    }

    @Override
    public String toString() {
        return super.toString();
    }

    static {
        Icmp6.ICMP6_REGISTRY.add(ROUTER_RENUMBERING_COMMAND);
        Icmp6.ICMP6_REGISTRY.add(ROUTER_RENUMBERING_RESULT);
        Icmp6.ICMP6_REGISTRY.add(SEQUENCE_NUMBER_RESET);
    }

}
