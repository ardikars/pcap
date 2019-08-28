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

    public static final TransportLayer ICMP = new TransportLayer((byte) 1, "Internet Control Message Protocol Version 4");

    public static final TransportLayer IPV6 = new TransportLayer((byte) 41, "IPv6 Header.");

    public static final TransportLayer IPV6_ICMP = new TransportLayer((byte) 58, "Internet Control Message Protocol Version 6");

    public static final TransportLayer IPV6_ROUTING = new TransportLayer((byte) 43, "Routing Header for IPv6.");

    public static final TransportLayer IPV6_FRAGMENT = new TransportLayer((byte) 44, "Fragment Header for IPv6.");

    public static final TransportLayer IPV6_HOPOPT = new TransportLayer((byte) 0, "IPv6 Hop by Hop NeighborDiscoveryOptions.");

    public static final TransportLayer IPV6_DSTOPT = new TransportLayer((byte) 60, "IPv6 Destination NeighborDiscoveryOptions.");

    public static final TransportLayer IPV6_ESP = new TransportLayer((byte) 50, "IPv6 ESP.");

    public static final TransportLayer IPV6_AH = new TransportLayer((byte) 51, "IPv6 Authentication Header.");

    public static final TransportLayer IGMP = new TransportLayer((byte) 2, "Internet Group Management Protocol");

    public static final TransportLayer TCP = new TransportLayer((byte) 6, "Transmission Control Protocol");

    public static final TransportLayer UDP = new TransportLayer((byte) 17, "User Datagram Protocol");

    public static final TransportLayer UNKNOWN = new TransportLayer((byte) -1, "Unknown");

    private static Map<Byte, TransportLayer> REGISTRY = new HashMap<Byte, TransportLayer>();

    private static Map<Byte, AbstractPacket.Builder> BUILDER = new HashMap<Byte, AbstractPacket.Builder>();

    protected TransportLayer(Byte value, String name) {
        super(value, name);
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
     *
     * @param type type
     */
    public static void register(final TransportLayer type) {
        REGISTRY.put(type.getValue(), type);
    }

    /**
     *
     * @param type type.
     * @param packetBuilder packet builder.
     */
    public static void register(TransportLayer type, AbstractPacket.Builder packetBuilder) {
        BUILDER.put(type.getValue(), packetBuilder);
    }

    static {
        REGISTRY.put(ICMP.getValue(), ICMP);
        REGISTRY.put(IPV6.getValue(), IPV6);
        REGISTRY.put(IPV6_ICMP.getValue(), IPV6_ICMP);
        REGISTRY.put(IPV6_ROUTING.getValue(), IPV6_ROUTING);
        REGISTRY.put(IPV6_FRAGMENT.getValue(), IPV6_FRAGMENT);
        REGISTRY.put(IPV6_HOPOPT.getValue(), IPV6_HOPOPT);
        REGISTRY.put(IPV6_DSTOPT.getValue(), IPV6_DSTOPT);
        REGISTRY.put(IPV6_ESP.getValue(), IPV6_ESP);
        REGISTRY.put(IPV6_AH.getValue(), IPV6_AH);
        REGISTRY.put(IGMP.getValue(), IGMP);
        REGISTRY.put(TCP.getValue(), TCP);
        REGISTRY.put(UDP.getValue(), UDP);
    }

}
