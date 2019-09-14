/** This code is licenced under the GPL version 2. */
package pcap.codec.icmp.icmp6;

import pcap.codec.icmp.Icmp;
import pcap.codec.icmp.Icmp6;
import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class Icmp6NeighborAdvertisement extends Icmp.IcmpTypeAndCode {

  public static final Icmp6NeighborAdvertisement NEIGHBOR_ADVERTISEMENT =
      new Icmp6NeighborAdvertisement((byte) 0, "Neighbor advertisement");

  public Icmp6NeighborAdvertisement(Byte code, String name) {
    super((byte) 136, code, name);
  }

  /**
   * Add new {@link Icmp6NeighborAdvertisement} to registry.
   *
   * @param code icmp type code.
   * @param name icmp type name.
   * @return returns {@link Icmp6NeighborAdvertisement}.
   */
  public static Icmp6NeighborAdvertisement register(Byte code, String name) {
    return new Icmp6NeighborAdvertisement(code, name);
  }

  @Override
  public String toString() {
    return super.toString();
  }

  static {
    Icmp6.ICMP6_REGISTRY.add(NEIGHBOR_ADVERTISEMENT);
  }
}
