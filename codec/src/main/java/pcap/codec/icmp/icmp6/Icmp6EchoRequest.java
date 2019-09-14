/** This code is licenced under the GPL version 2. */
package pcap.codec.icmp.icmp6;

import pcap.codec.icmp.Icmp;
import pcap.codec.icmp.Icmp6;
import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class Icmp6EchoRequest extends Icmp.IcmpTypeAndCode {

  public static final Icmp6EchoRequest ECHO_REQUEST =
      new Icmp6EchoRequest((byte) 0, "Echo request");

  public Icmp6EchoRequest(Byte code, String name) {
    super((byte) 128, code, name);
  }

  /**
   * Add new {@link Icmp6EchoRequest} to registry.
   *
   * @param code icmp type code.
   * @param name icmp type name.
   * @return returns {@link Icmp6EchoRequest}.
   */
  public static Icmp6EchoRequest register(Byte code, String name) {
    return new Icmp6EchoRequest(code, name);
  }

  @Override
  public String toString() {
    return super.toString();
  }

  static {
    Icmp6.ICMP6_REGISTRY.add(ECHO_REQUEST);
  }
}
