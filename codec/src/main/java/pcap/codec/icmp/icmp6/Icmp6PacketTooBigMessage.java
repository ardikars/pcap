/**
 * This code is licenced under the GPL version 2.
 */
package pcap.codec.icmp.icmp6;

import pcap.codec.icmp.Icmp;
import pcap.codec.icmp.Icmp6;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public class Icmp6PacketTooBigMessage extends Icmp.IcmpTypeAndCode {

    /**
     * A Packet Too Big MUST be sent by a router in response to a packet
     * that it cannot forward because the packet is larger than the MTU of
     * the outgoing link.  The information in this message is used as part
     * of the Path MTU Discovery process [PMTU].
     *
     * Originating a Packet Too Big Message makes an exception to one of the
     * rules as to when to originate an Icmp6InverseNeighborDiscoverySolicitation error message.  Unlike other
     * messages, it is sent in response to a packet received with an IPv6
     * multicast destination address, or with a link-layer multicast or
     * link-layer broadcast address.
     */

    public static final Icmp6PacketTooBigMessage PACKET_TOO_BIG_MESSAGE =
            new Icmp6PacketTooBigMessage((byte) 0, "Packet too big message");

    public Icmp6PacketTooBigMessage(Byte code, String name) {
        super((byte) 2, code, name);
    }

    /**
     * Add new {@link Icmp6PacketTooBigMessage} to registry.
     * @param code icmp type code.
     * @param name icmp type name.
     * @return returns {@link Icmp6PacketTooBigMessage}.
     */
    public static Icmp6PacketTooBigMessage register(Byte code, String name) {
        return new Icmp6PacketTooBigMessage(code, name);
    }

    @Override
    public String toString() {
        return super.toString();
    }

    static {
        Icmp6.ICMP6_REGISTRY.add(PACKET_TOO_BIG_MESSAGE);
    }

}
