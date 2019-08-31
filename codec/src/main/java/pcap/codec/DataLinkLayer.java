/**
 * This code is licenced under the GPL version 2.
 */
package pcap.codec;

import pcap.common.memory.Memory;
import pcap.common.util.NamedNumber;

import java.util.HashMap;
import java.util.Map;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public final class DataLinkLayer extends NamedNumber<Short, DataLinkLayer> {

    private static final Map<DataLinkLayer, Short> REGISTRY =
            new HashMap<DataLinkLayer, Short>();

    private static final Map<Short, AbstractPacket.Builder> BUILDER =
            new HashMap<Short, AbstractPacket.Builder>();

    public DataLinkLayer(int value, String name) {
        super((short) value, name);
    }

    public Packet newInstance(Memory buffer) {
        AbstractPacket.Builder packetBuilder = BUILDER.get(this.getValue());
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
     *
     * @param dataLinkLayer data link type.
     * @param packetBuilder packet builder.
     */
    public synchronized static void register(DataLinkLayer dataLinkLayer, AbstractPacket.Builder packetBuilder) {
        BUILDER.put(dataLinkLayer.getValue(), packetBuilder);
        REGISTRY.put(dataLinkLayer, dataLinkLayer.getValue());
    }

}
