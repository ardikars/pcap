/** This code is licenced under the GPL version 2. */
package pcap.codec.icmp.icmp4;

import pcap.codec.icmp.Icmp;
import pcap.codec.icmp.Icmp4;
import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class Icmp4TimestampReply extends Icmp.IcmpTypeAndCode {

  public static final Icmp4TimestampReply TIMESTAMP_REPLY =
      new Icmp4TimestampReply((byte) 0, "Timestamp reply");

  public Icmp4TimestampReply(Byte code, String name) {
    super((byte) 14, code, name);
  }

  /**
   * Add new {@link Icmp4TimestampReply} to registry.
   *
   * @param code icmp type code.
   * @param name icmp type name.
   * @return returns {@link Icmp4TimestampReply}.
   */
  public static Icmp4TimestampReply register(Byte code, String name) {
    return new Icmp4TimestampReply(code, name);
  }

  @Override
  public String toString() {
    return super.toString();
  }

  static {
    Icmp.IcmpTypeAndCode.ICMP4_REGISTRY.add(TIMESTAMP_REPLY);
  }
}
