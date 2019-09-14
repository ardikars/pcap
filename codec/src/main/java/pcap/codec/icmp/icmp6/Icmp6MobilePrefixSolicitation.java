/** This code is licenced under the GPL version 2. */
package pcap.codec.icmp.icmp6;

import pcap.codec.icmp.Icmp;
import pcap.codec.icmp.Icmp6;
import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class Icmp6MobilePrefixSolicitation extends Icmp.IcmpTypeAndCode {

  public static final Icmp6MobilePrefixSolicitation MOBILE_PREFIX_SOLICITATION =
      new Icmp6MobilePrefixSolicitation((byte) 0, "Mobile Prefix Solicitation");

  public Icmp6MobilePrefixSolicitation(Byte code, String name) {
    super((byte) 146, code, name);
  }

  /**
   * Add new {@link Icmp6MobilePrefixSolicitation} to registry.
   *
   * @param code icmp type code.
   * @param name icmp type name.
   * @return returns {@link Icmp6MobilePrefixSolicitation}.
   */
  public static Icmp6MobilePrefixSolicitation register(Byte code, String name) {
    return new Icmp6MobilePrefixSolicitation(code, name);
  }

  @Override
  public String toString() {
    return super.toString();
  }

  static {
    Icmp6.ICMP6_REGISTRY.add(MOBILE_PREFIX_SOLICITATION);
  }
}
