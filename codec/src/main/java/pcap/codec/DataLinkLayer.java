/** This code is licenced under the GPL version 2. */
package pcap.codec;

import java.util.HashMap;
import java.util.Map;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;
import pcap.common.util.NamedNumber;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public final class DataLinkLayer extends NamedNumber<Short, DataLinkLayer> {

  private static final Map<DataLinkLayer, Short> REGISTRY = new HashMap<DataLinkLayer, Short>();

  private static final Map<Short, AbstractPacket.Builder> BUILDER =
      new HashMap<Short, AbstractPacket.Builder>();

  /** Ethernet (10Mb, 100Mb, 1000Mb, and up): 1 */
  public static final DataLinkLayer EN10MB = new DataLinkLayer((short) 1, "Ethernet");

  public DataLinkLayer(int value, String name) {
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
   * @param value value.
   * @return returns {@link DataLinkLayer} object.
   */
  public static DataLinkLayer valueOf(short value) {
    for (Map.Entry<DataLinkLayer, Short> entry : REGISTRY.entrySet()) {
      if (entry.getValue() == value) {
        return entry.getKey();
      }
    }
    return new DataLinkLayer((short) -1, "Unknown");
  }

  /**
   * @param dataLinkLayer data link type.
   * @param packetBuilder packet builder.
   */
  public static synchronized void register(
      DataLinkLayer dataLinkLayer, AbstractPacket.Builder packetBuilder) {
    BUILDER.put(dataLinkLayer.value(), packetBuilder);
    REGISTRY.put(dataLinkLayer, dataLinkLayer.value());
  }
}
