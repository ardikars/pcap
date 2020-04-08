/** This code is licenced under the GPL version 2. */
package pcap.codec.icmp.icmp4;

import pcap.codec.icmp.Icmp;
import pcap.codec.icmp.Icmp4;
import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class Icmp4Timestamp extends Icmp.IcmpTypeAndCode {

  public static final Icmp4Timestamp TIMESTAMP = new Icmp4Timestamp((byte) 0, "Timestamp");

  public Icmp4Timestamp(Byte code, String name) {
    super((byte) 13, code, name);
  }

  /**
   * Add new {@link Icmp4Timestamp} to registry.
   *
   * @param code icmp type code.
   * @param name icmp type name.
   * @return returns {@link Icmp4Timestamp}.
   */
  public static Icmp4Timestamp register(Byte code, String name) {
    return new Icmp4Timestamp(code, name);
  }

  @Override
  public String toString() {
    return super.toString();
  }

  static {
    Icmp.IcmpTypeAndCode.ICMP4_REGISTRY.add(TIMESTAMP);
  }
}
