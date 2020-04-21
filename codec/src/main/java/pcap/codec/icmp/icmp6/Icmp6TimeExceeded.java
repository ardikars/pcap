/** This code is licenced under the GPL version 2. */
package pcap.codec.icmp.icmp6;

import pcap.codec.icmp.Icmp;
import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class Icmp6TimeExceeded extends Icmp.IcmpTypeAndCode {

  public static final Icmp6TimeExceeded HOP_LIMIT_EXCEEDED_IN_TRANSIT =
      new Icmp6TimeExceeded((byte) 0, "Hop limit exceeded in transit");

  public static final Icmp6TimeExceeded FRAGMENT_REASSEMBLY_TIME_EXCEEDED =
      new Icmp6TimeExceeded((byte) 1, "Fragment reassembly time exceeded");

  public Icmp6TimeExceeded(Byte code, String name) {
    super((byte) 3, code, name);
  }

  /**
   * Add new {@link Icmp6TimeExceeded} type to registry.
   *
   * @param code icmp type code.
   * @param name icmp type name.
   * @return returns {@link Icmp6TimeExceeded}.
   */
  public static Icmp6TimeExceeded register(Byte code, String name) {
    return new Icmp6TimeExceeded(code, name);
  }

  @Override
  public String toString() {
    return super.toString();
  }

  static {
    Icmp.IcmpTypeAndCode.ICMP6_REGISTRY.add(HOP_LIMIT_EXCEEDED_IN_TRANSIT);
    Icmp.IcmpTypeAndCode.ICMP6_REGISTRY.add(FRAGMENT_REASSEMBLY_TIME_EXCEEDED);
  }
}
