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

    /**
     * Ethernet (10Mb, 100Mb, 1000Mb, and up): 1
     */
    public static final DataLinkLayer EN10MB = new DataLinkLayer((short) 1, "Ethernet");

    /**
     * Linux cooked-mode capture (SLL): 113
     */
    public static final DataLinkLayer LINUX_SLL = new DataLinkLayer((short) 113, "Linux SLL");

    private static final Map<DataLinkLayer, Short> REGISTRY =
            new HashMap<DataLinkLayer, Short>();

    private static final Map<Short, AbstractPacket.Builder> builder =
            new HashMap<Short, AbstractPacket.Builder>();

    public DataLinkLayer(Short value, String name) {
        super(value, name);
    }

    public Packet newInstance(Memory buffer) {
        AbstractPacket.Builder packetBuilder = builder.get(this.getValue());
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
     */
    public static void register(DataLinkLayer dataLinkLayer) {
        synchronized (REGISTRY) {
            REGISTRY.put(dataLinkLayer, dataLinkLayer.getValue());
        }
    }

    /**
     *
     * @param dataLinkLayer data link type.
     * @param packetBuilder packet builder.
     */
    public static void register(DataLinkLayer dataLinkLayer, AbstractPacket.Builder packetBuilder) {
        synchronized (builder) {
            builder.put(dataLinkLayer.getValue(), packetBuilder);
        }
    }

    static {
        REGISTRY.put(EN10MB, EN10MB.getValue());
        REGISTRY.put(LINUX_SLL, LINUX_SLL.getValue());
    }

}
