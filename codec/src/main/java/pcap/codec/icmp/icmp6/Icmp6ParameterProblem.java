/**
 * This code is licenced under the GPL version 2.
 */
package pcap.codec.icmp.icmp6;

import pcap.codec.icmp.Icmp;
import pcap.codec.icmp.Icmp6;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public class Icmp6ParameterProblem extends Icmp.IcmpTypeAndCode {

    public static final Icmp6ParameterProblem ERRORNEOUS_HEADER_FIELD_ENCOUTERED =
            new Icmp6ParameterProblem((byte) 0, "Erroneous header field encountered");

    public static final Icmp6ParameterProblem UNRECOGNIZED_NEXT_HEADER_TYPE_ENCOUNTERED =
            new Icmp6ParameterProblem((byte) 1, "Unrecognized Next HeaderAbstract type encountered");

    public static final Icmp6ParameterProblem UNRECOGNIZED_IPV6_OPTION_ENCOUNTERED =
            new Icmp6ParameterProblem((byte) 2, "Unrecognized IPv6 option encountered");

    public Icmp6ParameterProblem(Byte code, String name) {
        super((byte) 4, code, name);
    }

    /**
     * Add new {@link Icmp6ParameterProblem}.
     * @param code icmp type code.
     * @param name icmp type name.
     * @return returns {@link Icmp6ParameterProblem}.
     */
    public static Icmp6ParameterProblem register(Byte code, String name) {
        return new Icmp6ParameterProblem(code, name);
    }

    @Override
    public String toString() {
        return super.toString();
    }

    static {
        Icmp6.ICMP6_REGISTRY.add(ERRORNEOUS_HEADER_FIELD_ENCOUTERED);
        Icmp6.ICMP6_REGISTRY.add(UNRECOGNIZED_NEXT_HEADER_TYPE_ENCOUNTERED);
        Icmp6.ICMP6_REGISTRY.add(UNRECOGNIZED_IPV6_OPTION_ENCOUNTERED);
    }

}
