package pcap.codec.icmp.icmp6;

import pcap.codec.icmp.Icmp;
import pcap.codec.icmp.Icmp6;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public class Icmp6NodeInformationQuery extends Icmp.IcmpTypeAndCode {

    public static final Icmp6NodeInformationQuery DATA_FIELD_CONTAINS_IPV6_ADDRESS =
            new Icmp6NodeInformationQuery((byte) 0, "Data field contains an IPv6 address");

    public static final Icmp6NodeInformationQuery DATA_FIELD_CONTAIONS_NAME =
            new Icmp6NodeInformationQuery((byte) 1, "Data field contains a name which is the Subject of this Query");

    public static final Icmp6NodeInformationQuery DATA_FIELD_CONTAINS_IPV4_ADDRESS =
            new Icmp6NodeInformationQuery((byte) 2, "Data field contains an IPv4 address");

    public Icmp6NodeInformationQuery(Byte code, String name) {
        super((byte) 139, code, name);
    }

    /**
     * Add new {@link Icmp6NodeInformationQuery} to registry.
     * @param code icmp type code.
     * @param name icmp type name.
     * @return returns {@link Icmp6NodeInformationQuery}.
     */
    public static Icmp6NodeInformationQuery register(Byte code, String name) {
        return new Icmp6NodeInformationQuery(code, name);
    }

    @Override
    public String toString() {
        return super.toString();
    }

    static {
        Icmp6.ICMP6_REGISTRY.add(DATA_FIELD_CONTAINS_IPV6_ADDRESS);
        Icmp6.ICMP6_REGISTRY.add(DATA_FIELD_CONTAIONS_NAME);
        Icmp6.ICMP6_REGISTRY.add(DATA_FIELD_CONTAINS_IPV4_ADDRESS);
    }

}
