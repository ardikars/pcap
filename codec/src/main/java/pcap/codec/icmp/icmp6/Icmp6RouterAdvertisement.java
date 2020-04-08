/** This code is licenced under the GPL version 2. */
package pcap.codec.icmp.icmp6;

import pcap.codec.icmp.Icmp;
import pcap.codec.icmp.Icmp6;
import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class Icmp6RouterAdvertisement extends Icmp.IcmpTypeAndCode {

  public static final Icmp6RouterAdvertisement ROUTER_ADVERTISEMENT =
      new Icmp6RouterAdvertisement((byte) 0, "Router advertisment");

  public Icmp6RouterAdvertisement(Byte code, String name) {
    super((byte) 134, code, name);
  }

  /**
   * Add new {@link Icmp6RouterAdvertisement} to registry.
   *
   * @param code icmp type code.
   * @param name icmp type name.
   * @return returns {@link Icmp6RouterAdvertisement}.
   */
  public static Icmp6RouterAdvertisement register(Byte code, String name) {
    return new Icmp6RouterAdvertisement(code, name);
  }

  @Override
  public String toString() {
    return super.toString();
  }

  static {
    Icmp.IcmpTypeAndCode.ICMP6_REGISTRY.add(ROUTER_ADVERTISEMENT);
  }
}
