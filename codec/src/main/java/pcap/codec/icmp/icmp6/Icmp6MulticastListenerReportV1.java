/** This code is licenced under the GPL version 2. */
package pcap.codec.icmp.icmp6;

import pcap.codec.icmp.Icmp;
import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class Icmp6MulticastListenerReportV1 extends Icmp.IcmpTypeAndCode {

  public static final Icmp6MulticastListenerReportV1 MULTICAST_LISTENER_REPORT =
      new Icmp6MulticastListenerReportV1((byte) 0, "Multicast listener report");

  public Icmp6MulticastListenerReportV1(Byte code, String name) {
    super((byte) 131, code, name);
  }

  /**
   * Add new {@link Icmp6MulticastListenerReportV1} to registry.
   *
   * @param code icmp type code.
   * @param name icmp type name.
   * @return returns {@link Icmp6MulticastListenerReportV1}.
   */
  public static Icmp6MulticastListenerReportV1 register(Byte code, String name) {
    return new Icmp6MulticastListenerReportV1(code, name);
  }

  @Override
  public String toString() {
    return super.toString();
  }

  static {
    Icmp.IcmpTypeAndCode.ICMP6_REGISTRY.add(MULTICAST_LISTENER_REPORT);
  }
}
