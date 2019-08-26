package pcap.codec.icmp.icmp6;

import pcap.codec.icmp.Icmp;
import pcap.codec.icmp.Icmp6;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public class Icmp6NodeInformationResponse extends Icmp.IcmpTypeAndCode {

    public static final Icmp6NodeInformationResponse SUCCESSFULL_REPLY =
            new Icmp6NodeInformationResponse((byte) 0, "A successfull reply");

    public static final Icmp6NodeInformationResponse RESPONDER_REFUSES_TO_SUPPLY_THE_ASWER =
            new Icmp6NodeInformationResponse((byte) 1, "The Responder refuses to supply the answer");

    public static final Icmp6NodeInformationResponse QTYPE_OF_THE_QUERY_IS_UNKNOWN_TO_THE_RESPONDER =
            new Icmp6NodeInformationResponse((byte) 2, "The Qtype of the Query is unknown to the Responder");

    public Icmp6NodeInformationResponse(Byte code, String name) {
        super((byte) 140, code, name);
    }

    /**
     * Add new {@link Icmp6NodeInformationResponse} to registry.
     * @param code icmp type code.
     * @param name icmp type name.
     * @return returns {@link Icmp6NodeInformationResponse}.
     */
    public static Icmp6NodeInformationResponse register(Byte code, String name) {
        return new Icmp6NodeInformationResponse(code, name);
    }

    @Override
    public String toString() {
        return super.toString();
    }

    static {
        Icmp6.ICMP6_REGISTRY.add(SUCCESSFULL_REPLY);
        Icmp6.ICMP6_REGISTRY.add(RESPONDER_REFUSES_TO_SUPPLY_THE_ASWER);
        Icmp6.ICMP6_REGISTRY.add(QTYPE_OF_THE_QUERY_IS_UNKNOWN_TO_THE_RESPONDER);
    }

}
