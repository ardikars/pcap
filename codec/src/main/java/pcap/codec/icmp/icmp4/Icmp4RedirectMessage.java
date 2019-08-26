package pcap.codec.icmp.icmp4;

import pcap.codec.icmp.Icmp;
import pcap.codec.icmp.Icmp4;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public class Icmp4RedirectMessage extends Icmp.IcmpTypeAndCode {

    public static final Icmp4RedirectMessage REDIRECT_DATAGRAM_FOR_NETWORK =
            new Icmp4RedirectMessage((byte) 0, "Redirect datagram for the network");

    public Icmp4RedirectMessage(Byte code, String name) {
        super((byte) 5, code, name);
    }

    public static Icmp4RedirectMessage register(Byte code, String name) {
        return new Icmp4RedirectMessage(code, name);
    }

    @Override
    public String toString() {
        return super.toString();
    }

    static {
        Icmp4.ICMP4_REGISTRY.add(REDIRECT_DATAGRAM_FOR_NETWORK);
    }

}
