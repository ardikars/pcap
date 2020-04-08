/** This code is licenced under the GPL version 2. */
package pcap.codec.icmp.icmp6;

import pcap.codec.icmp.Icmp;
import pcap.codec.icmp.Icmp6;
import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class Icmp6RedirectMessage extends Icmp.IcmpTypeAndCode {

  public static final Icmp6RedirectMessage REDIRECT_MESSAGE =
      new Icmp6RedirectMessage((byte) 0, "Redirect message");

  public Icmp6RedirectMessage(Byte code, String name) {
    super((byte) 137, code, name);
  }

  /**
   * Add new {@link Icmp6RedirectMessage} to registry.
   *
   * @param code icmp type code.
   * @param name icmp type name.
   * @return returns {@link Icmp6RedirectMessage}.
   */
  public static Icmp6RedirectMessage register(Byte code, String name) {
    return new Icmp6RedirectMessage(code, name);
  }

  @Override
  public String toString() {
    return super.toString();
  }

  static {
    Icmp.IcmpTypeAndCode.ICMP6_REGISTRY.add(REDIRECT_MESSAGE);
  }
}
