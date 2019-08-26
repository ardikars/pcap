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
public final class NetworkLayer extends NamedNumber<Short, NetworkLayer> {

    public static final int IEEE802_3_MAX_LENGTH = 1500;

    /**
     * IPv4: 0x0800
     */
    public static final NetworkLayer IPV4
            = new NetworkLayer((short) 0x0800, "IPv4");

    /**
     * Arp: 0x0806
     */
    public static final NetworkLayer ARP
            = new NetworkLayer((short) 0x0806, "Arp");

    /**
     * IEEE 802.1Q VLAN-tagged frames: 0x8100
     */
    public static final NetworkLayer DOT1Q_VLAN_TAGGED_FRAMES
            = new NetworkLayer((short) 0x8100, "IEEE 802.1Q VLAN-tagged frames");

    /**
     * QinQ: 0x88a8
     */
    public static final NetworkLayer IEEE_802_1_AD
            = new NetworkLayer((short) 0x88a8, "QinQ");
    /**
     * RARP: 0x8035
     */
    public static final NetworkLayer RARP
            = new NetworkLayer((short) 0x8035, "RARP");

    /**
     * Appletalk: 0x809b
     */
    public static final NetworkLayer APPLETALK
            = new NetworkLayer((short) 0x809b, "Appletalk");

    /**
     * IPv6: 0x86dd
     */
    public static final NetworkLayer IPV6
            = new NetworkLayer((short) 0x86dd, "IPv6");

    /**
     * PPP: 0x880b
     */
    public static final NetworkLayer PPP
            = new NetworkLayer((short) 0x880b, "PPP");

    /**
     * MPLS: 0x8847
     */
    public static final NetworkLayer MPLS
            = new NetworkLayer((short) 0x8847, "MPLS");

    /**
     * PPPoED Discovery Stage: 0x8863
     */
    public static final NetworkLayer PPPOE_DISCOVERY_STAGE
            = new NetworkLayer((short) 0x8863, "PPPoED Discovery Stage");

    /**
     * PPPoED Session Stage: 0x8864
     */
    public static final NetworkLayer PPPOE_SESSION_STAGE
            = new NetworkLayer((short) 0x8864, "PPPoED Session Stage");

    public static final NetworkLayer UNKNOWN
            = new NetworkLayer((short) -1, "Unknown");

    private static final Map<Short, NetworkLayer> registry
            = new HashMap<Short, NetworkLayer>();

    private static final Map<Short, AbstractPacket.Builder> builder
            = new HashMap<Short, AbstractPacket.Builder>();

    /**
     * @param value value
     * @param name  name
     */
    public NetworkLayer(Short value, String name) {
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
     * @param value value
     * @return returns {@link NetworkLayer} object.
     */
    public static NetworkLayer valueOf(final Short value) {
        if ((value & 0xFFFF) <= IEEE802_3_MAX_LENGTH) {
            return UNKNOWN;
        }
        NetworkLayer protocolType = registry.get(value);
        if (protocolType == null) {
            return UNKNOWN;
        }
        return protocolType;
    }

    /**
     * @param type type.
     */
    public static void register(NetworkLayer type) {
        synchronized (registry) {
            registry.put(type.getValue(), type);
        }
    }

    /**
     *
     * @param networkLayer type.
     * @param packetBuilder packet builder.
     */
    public static void register(NetworkLayer networkLayer, AbstractPacket.Builder packetBuilder) {
        synchronized (builder) {
            builder.put(networkLayer.getValue(), packetBuilder);
        }
    }

    @Override
    public String toString() {
        return super.toString();
    }

    static {
        registry.put(IPV4.getValue(), IPV4);
        registry.put(ARP.getValue(), ARP);
        registry.put(DOT1Q_VLAN_TAGGED_FRAMES.getValue(), DOT1Q_VLAN_TAGGED_FRAMES);
        registry.put(RARP.getValue(), RARP);
        registry.put(APPLETALK.getValue(), APPLETALK);
        registry.put(IPV6.getValue(), IPV6);
        registry.put(PPP.getValue(), PPP);
        registry.put(MPLS.getValue(), MPLS);
        registry.put(PPPOE_DISCOVERY_STAGE.getValue(), PPPOE_DISCOVERY_STAGE);
        registry.put(PPPOE_SESSION_STAGE.getValue(), PPPOE_SESSION_STAGE);
        registry.put(IEEE_802_1_AD.getValue(), IEEE_802_1_AD);
    }

}
