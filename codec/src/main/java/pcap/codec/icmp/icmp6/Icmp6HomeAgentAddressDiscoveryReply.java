/** This code is licenced under the GPL version 2. */
package pcap.codec.icmp.icmp6;

import pcap.codec.icmp.Icmp;
import pcap.codec.icmp.Icmp6;
import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class Icmp6HomeAgentAddressDiscoveryReply extends Icmp.IcmpTypeAndCode {

  public static final Icmp6HomeAgentAddressDiscoveryReply HOME_AGENT_ADDRESS_DISCOVERY_REPLY =
      new Icmp6HomeAgentAddressDiscoveryReply(
          (byte) 0, "Home Agent Address Discovery Reply Message");

  public Icmp6HomeAgentAddressDiscoveryReply(Byte code, String name) {
    super((byte) 145, code, name);
  }

  /**
   * Add new {@link Icmp6HomeAgentAddressDiscoveryReply} to registry.
   *
   * @param code icmp type code.
   * @param name icmp type name.
   * @return returns {@link Icmp6HomeAgentAddressDiscoveryReply}.
   */
  public static Icmp6HomeAgentAddressDiscoveryReply register(Byte code, String name) {
    return new Icmp6HomeAgentAddressDiscoveryReply(code, name);
  }

  @Override
  public String toString() {
    return super.toString();
  }

  static {
    Icmp6.ICMP6_REGISTRY.add(HOME_AGENT_ADDRESS_DISCOVERY_REPLY);
  }
}
