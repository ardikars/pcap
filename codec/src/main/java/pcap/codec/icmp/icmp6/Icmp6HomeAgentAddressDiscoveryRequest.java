/**
 * This code is licenced under the GPL version 2.
 */
package pcap.codec.icmp.icmp6;

import pcap.codec.icmp.Icmp;
import pcap.codec.icmp.Icmp6;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public class Icmp6HomeAgentAddressDiscoveryRequest extends Icmp.IcmpTypeAndCode {

    public static final Icmp6HomeAgentAddressDiscoveryRequest HOME_AGENT_ADDRESS_DISCOVERY_REQUEST =
            new Icmp6HomeAgentAddressDiscoveryRequest((byte) 0, "Home Agent Address Discovery Request Message");

    public Icmp6HomeAgentAddressDiscoveryRequest(Byte code, String name) {
        super((byte) 144, code, name);
    }

    /**
     * Add new {@link Icmp6HomeAgentAddressDiscoveryRequest} to registry.
     * @param code icmp type code.
     * @param name icmp type name.
     * @return returns {@link Icmp6HomeAgentAddressDiscoveryRequest}.
     */
    public static Icmp6HomeAgentAddressDiscoveryRequest register(Byte code, String name) {
        return new Icmp6HomeAgentAddressDiscoveryRequest(code, name);
    }

    @Override
    public String toString() {
        return super.toString();
    }

    static {
        Icmp6.ICMP6_REGISTRY.add(HOME_AGENT_ADDRESS_DISCOVERY_REQUEST);
    }

}
