/** This code is licenced under the GPL version 2. */
package pcap.codec.icmp.icmp6;

import pcap.codec.icmp.Icmp;
import pcap.codec.icmp.Icmp6;
import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class Icmp6MulticastListenerDone extends Icmp.IcmpTypeAndCode {

  public static final Icmp6MulticastListenerDone MULTICAST_LISTENER_DONE =
      new Icmp6MulticastListenerDone((byte) 0, "Multicast listener done");

  public Icmp6MulticastListenerDone(Byte code, String name) {
    super((byte) 132, code, name);
  }

  /**
   * Add new {@link Icmp6MulticastListenerDone} to registry.
   *
   * @param code icmp type name.
   * @param name icmp type code.
   * @return returns {@link Icmp6MulticastListenerDone}.
   */
  public static Icmp6MulticastListenerDone register(Byte code, String name) {
    return new Icmp6MulticastListenerDone(code, name);
  }

  @Override
  public String toString() {
    return super.toString();
  }

  static {
    Icmp.IcmpTypeAndCode.ICMP6_REGISTRY.add(MULTICAST_LISTENER_DONE);
  }
}
