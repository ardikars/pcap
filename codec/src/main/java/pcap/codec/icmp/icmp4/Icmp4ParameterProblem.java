package pcap.codec.icmp.icmp4;

import pcap.codec.icmp.Icmp;
import pcap.codec.icmp.Icmp4;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public class Icmp4ParameterProblem extends Icmp.IcmpTypeAndCode {

    public static final Icmp4ParameterProblem POINTER_INDICATES_THE_ERROR =
            new Icmp4ParameterProblem((byte) 0, "Pointer indicates the error");

    public static final Icmp4ParameterProblem MISSING_REQUIRED_OPTION =
            new Icmp4ParameterProblem((byte) 1, "Missing a required option");

    public static final Icmp4ParameterProblem BAD_LENGTH =
            new Icmp4ParameterProblem((byte) 2, "Bad length");

    public Icmp4ParameterProblem(Byte code, String name) {
        super((byte) 12, code, name);
    }

    /**
     * Add new {@link Icmp4ParameterProblem} to registry.
     * @param code icmp type code.
     * @param name icmp type name.
     * @return returns {@link Icmp4ParameterProblem}.
     */
    public static Icmp4ParameterProblem register(Byte code, String name) {
        return new Icmp4ParameterProblem(code, name);
    }

    @Override
    public String toString() {
        return super.toString();
    }

    static {
        Icmp4.ICMP4_REGISTRY.add(POINTER_INDICATES_THE_ERROR);
        Icmp4.ICMP4_REGISTRY.add(MISSING_REQUIRED_OPTION);
        Icmp4.ICMP4_REGISTRY.add(BAD_LENGTH);
    }

}
