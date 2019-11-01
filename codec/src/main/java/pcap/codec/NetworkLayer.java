/** This code is licenced under the GPL version 2. */
package pcap.codec;

import java.util.HashMap;
import java.util.Map;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;
import pcap.common.util.NamedNumber;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public final class NetworkLayer extends NamedNumber<Short, NetworkLayer> {

  public static final int IEEE802_3_MAX_LENGTH = 1500;

  public static final NetworkLayer UNKNOWN = new NetworkLayer((short) -1, "Unknown");

  private static final Map<Short, NetworkLayer> REGISTRY = new HashMap<Short, NetworkLayer>();

  private static final Map<Short, AbstractPacket.Builder> BUILDER =
      new HashMap<Short, AbstractPacket.Builder>();

  /** IPv4: 0x0800 */
  public static final NetworkLayer IPV4 = new NetworkLayer((short) 0x0800, "IPv4");

  /** Arp: 0x0806 */
  public static final NetworkLayer ARP = new NetworkLayer((short) 0x0806, "Arp");

  /** IEEE 802.1Q VLAN-tagged frames: 0x8100 */
  public static final NetworkLayer DOT1Q_VLAN_TAGGED_FRAMES =
      new NetworkLayer((short) 0x8100, "IEEE 802.1Q VLAN-tagged frames");

  /**
   * @param value value
   * @param name name
   */
  public NetworkLayer(int value, String name) {
    super((short) value, name);
  }

  public Packet newInstance(Memory buffer) {
    AbstractPacket.Builder packetBuilder = BUILDER.get(this.value());
    if (packetBuilder == null) {
      if (buffer == null || buffer.capacity() <= 0) {
        return null;
      }
      return new UnknownPacket.Builder().build(buffer);
    }
    return packetBuilder.build(buffer);
  }

  /**
   * @param value value
   * @return returns {@link NetworkLayer} object.
   */
  public static NetworkLayer valueOf(final Short value) {
    if ((value & 0xFFFF) <= IEEE802_3_MAX_LENGTH) {
      return UNKNOWN;
    }
    NetworkLayer protocolType = REGISTRY.get(value);
    if (protocolType == null) {
      return UNKNOWN;
    }
    return protocolType;
  }

  /**
   * @param networkLayer type.
   * @param packetBuilder packet builder.
   */
  public static synchronized void register(
      NetworkLayer networkLayer, AbstractPacket.Builder packetBuilder) {
    BUILDER.put(networkLayer.value(), packetBuilder);
    REGISTRY.put(networkLayer.value(), networkLayer);
  }

  @Override
  public String toString() {
    return super.toString();
  }
}
