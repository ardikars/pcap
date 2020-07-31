/** This code is licenced under the GPL version 2. */
package pcap.codec;

import java.util.HashMap;
import java.util.Map;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;
import pcap.common.util.NamedNumber;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public final class NetworkLayer extends NamedNumber<Short, NetworkLayer>
    implements ProtocolType<Short> {

  public static final int IEEE802_3_MAX_LENGTH = 1500;

  public static final NetworkLayer EMPTY = new NetworkLayer(0, "Empty");

  /** IPv4: 0x0800 */
  public static final NetworkLayer IPV4 = new NetworkLayer((short) 0x0800, "IPv4");
  /** Arp: 0x0806 */
  public static final NetworkLayer ARP = new NetworkLayer((short) 0x0806, "Arp");
  /** IEEE 802.1Q VLAN-tagged frames: 0x8100 */
  public static final NetworkLayer DOT1Q_VLAN_TAGGED_FRAMES =
      new NetworkLayer((short) 0x8100, "IEEE 802.1Q VLAN-tagged frames");
  /** QinQ: 0x88a8 */
  public static final NetworkLayer IEEE_802_1_AD = new NetworkLayer((short) 0x88a8, "QinQ");
  /** RARP: 0x8035 */
  public static final NetworkLayer RARP = new NetworkLayer((short) 0x8035, "RARP");
  /** Appletalk: 0x809b */
  public static final NetworkLayer APPLETALK = new NetworkLayer((short) 0x809b, "Appletalk");
  /** IPv6: 0x86dd */
  public static final NetworkLayer IPV6 = new NetworkLayer((short) 0x86dd, "IPv6");
  /** PPP: 0x880b */
  public static final NetworkLayer PPP = new NetworkLayer((short) 0x880b, "PPP");
  /** MPLS: 0x8847 */
  public static final NetworkLayer MPLS = new NetworkLayer((short) 0x8847, "MPLS");
  /** PPPoED Discovery Stage: 0x8863 */
  public static final NetworkLayer PPPOE_DISCOVERY_STAGE =
      new NetworkLayer((short) 0x8863, "PPPoED Discovery Stage");
  /** PPPoED Session Stage: 0x8864 */
  public static final NetworkLayer PPPOE_SESSION_STAGE =
      new NetworkLayer((short) 0x8864, "PPPoED Session Stage");

  private static final Map<Short, NetworkLayer> REGISTRY = new HashMap<>();
  private static final Map<Short, AbstractPacket.Builder> BUILDER = new HashMap<>();

  /**
   * @param value value
   * @param name name
   */
  public NetworkLayer(int value, String name) {
    super((short) value, name);
  }

  /**
   * @param value value
   * @return returns {@link NetworkLayer} object.
   */
  public static NetworkLayer valueOf(final Short value) {
    NetworkLayer unknown = new NetworkLayer(value, "Unknown");

    if ((value & 0xFFFF) <= IEEE802_3_MAX_LENGTH) {
      return unknown;
    }
    NetworkLayer protocolType = REGISTRY.get(value);
    if (protocolType == null) {
      return unknown;
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

  @Override
  public String toString() {
    return super.toString();
  }
}
