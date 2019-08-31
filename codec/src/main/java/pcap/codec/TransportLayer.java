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
public final class TransportLayer extends NamedNumber<Byte, TransportLayer> {

    public static final TransportLayer UNKNOWN = new TransportLayer((byte) -1, "Unknown");

    private static Map<Byte, TransportLayer> REGISTRY = new HashMap<Byte, TransportLayer>();

    private static Map<Byte, AbstractPacket.Builder> BUILDER = new HashMap<Byte, AbstractPacket.Builder>();

    public TransportLayer(int value, String name) {
        super((byte) value, name);
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

    public static TransportLayer valueOf(final Byte value) {
        TransportLayer transportLayer = REGISTRY.get(value);
        if (transportLayer == null) {
            return UNKNOWN;
        } else {
            return transportLayer;
        }
    }

    /**
     * @param type          type.
     * @param packetBuilder packet builder.
     */
    public synchronized static void register(TransportLayer type, AbstractPacket.Builder packetBuilder) {
        BUILDER.put(type.getValue(), packetBuilder);
        REGISTRY.put(type.getValue(), type);
    }

}
