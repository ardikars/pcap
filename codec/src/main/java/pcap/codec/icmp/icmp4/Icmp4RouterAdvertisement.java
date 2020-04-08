/** This code is licenced under the GPL version 2. */
package pcap.codec.icmp.icmp4;

import pcap.codec.icmp.Icmp;
import pcap.codec.icmp.Icmp4;
import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class Icmp4RouterAdvertisement extends Icmp.IcmpTypeAndCode {

  public static final Icmp4RouterAdvertisement ROUTER_ADVERTISEMENT =
      new Icmp4RouterAdvertisement((byte) 0, "Router Advertisement");

  public Icmp4RouterAdvertisement(Byte code, String name) {
    super((byte) 9, code, name);
  }

  /**
   * Add new {@link Icmp4RouterAdvertisement} to registry.
   *
   * @param code icmp type code.
   * @param name icmp type name.
   * @return returns {@link Icmp4RouterAdvertisement}.
   */
  public static Icmp4RouterAdvertisement register(Byte code, String name) {
    return new Icmp4RouterAdvertisement(code, name);
  }

  @Override
  public String toString() {
    return super.toString();
  }

  static {
    Icmp.IcmpTypeAndCode.ICMP4_REGISTRY.add(ROUTER_ADVERTISEMENT);
  }
}
