/** This code is licenced under the GPL version 2. */
package pcap.codec.icmp.icmp4;

import pcap.codec.icmp.Icmp;
import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class Icmp4EchoReply extends Icmp.IcmpTypeAndCode {

  public static final Icmp4EchoReply ECHO_REPLY =
      new Icmp4EchoReply((byte) 0, "Echo reply (used to ping)");

  public Icmp4EchoReply(Byte code, String name) {
    super((byte) 0, code, name);
  }

  /**
   * Add new {@link Icmp4EchoRequest} to registry.
   *
   * @param code icmp type code.
   * @param name icmp type name.
   * @return returns {@link Icmp4EchoRequest}.
   */
  public static Icmp4EchoReply register(Byte code, String name) {
    return new Icmp4EchoReply(code, name);
  }

  @Override
  public String toString() {
    return super.toString();
  }

  static {
    Icmp.IcmpTypeAndCode.ICMP4_REGISTRY.add(ECHO_REPLY);
  }
}
