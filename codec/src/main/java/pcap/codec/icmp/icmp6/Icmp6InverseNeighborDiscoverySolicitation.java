/** This code is licenced under the GPL version 2. */
package pcap.codec.icmp.icmp6;

import pcap.codec.icmp.Icmp;
import pcap.codec.icmp.Icmp6;
import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class Icmp6InverseNeighborDiscoverySolicitation extends Icmp.IcmpTypeAndCode {

  public static final Icmp6InverseNeighborDiscoverySolicitation
      INVERSE_NEIGHBOR_DISCOVERY_SOLICITATION =
          new Icmp6InverseNeighborDiscoverySolicitation(
              (byte) 0, "Inverse neighbor discovery solicitation message");

  public Icmp6InverseNeighborDiscoverySolicitation(Byte code, String name) {
    super((byte) 141, code, name);
  }

  /**
   * Add new {@link Icmp6InverseNeighborDiscoverySolicitation} to registry.
   *
   * @param code icmp type code.
   * @param name icmp type name.
   * @return returns {@link Icmp6InverseNeighborDiscoverySolicitation}.
   */
  public static Icmp6InverseNeighborDiscoverySolicitation register(Byte code, String name) {
    return new Icmp6InverseNeighborDiscoverySolicitation(code, name);
  }

  @Override
  public String toString() {
    return super.toString();
  }

  static {
    Icmp.IcmpTypeAndCode.ICMP6_REGISTRY.add(INVERSE_NEIGHBOR_DISCOVERY_SOLICITATION);
  }
}
