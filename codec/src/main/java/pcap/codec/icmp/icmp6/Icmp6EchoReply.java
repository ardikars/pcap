/** This code is licenced under the GPL version 2. */
package pcap.codec.icmp.icmp6;

import pcap.codec.icmp.Icmp;
import pcap.codec.icmp.Icmp6;
import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class Icmp6EchoReply extends Icmp.IcmpTypeAndCode {

  public static final Icmp6EchoReply ECHO_REPLY = new Icmp6EchoReply((byte) 0, "Echo  reply");

  public Icmp6EchoReply(Byte code, String name) {
    super((byte) 129, code, name);
  }

  /**
   * Add new {@link Icmp6EchoReply} to registry.
   *
   * @param code icmp type code.
   * @param name icmp type name.
   * @return returns {@link Icmp6EchoReply}.
   */
  public static Icmp6EchoReply register(Byte code, String name) {
    return new Icmp6EchoReply(code, name);
  }

  @Override
  public String toString() {
    return super.toString();
  }

  static {
    Icmp.IcmpTypeAndCode.ICMP6_REGISTRY.add(ECHO_REPLY);
  }
}
