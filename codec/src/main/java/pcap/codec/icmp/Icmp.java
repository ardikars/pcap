/** This code is licenced under the GPL version 2. */
package pcap.codec.icmp;

import java.util.*;

import pcap.codec.AbstractPacket;
import pcap.codec.Packet;
import pcap.codec.UnknownPacket;
import pcap.codec.ndp.NeighborAdvertisement;
import pcap.codec.ndp.NeighborSolicitation;
import pcap.codec.ndp.Redirect;
import pcap.codec.ndp.RouterAdvertisement;
import pcap.codec.ndp.RouterSolicitation;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;
import pcap.common.util.NamedNumber;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public abstract class Icmp extends AbstractPacket {

  protected static IcmpTypeAndCode findIcmpTypeAndCode(
      byte type, byte code, Collection<IcmpTypeAndCode> typeAndCodes) {
    Iterator<IcmpTypeAndCode> icmpTypeAndCodeIterator = typeAndCodes.iterator();
    while (icmpTypeAndCodeIterator.hasNext()) {
      IcmpTypeAndCode typeAndCode = icmpTypeAndCodeIterator.next();
      if (typeAndCode.type() == type && typeAndCode.code() == code) {
        return typeAndCode;
      }
    }
    return new IcmpTypeAndCode(type, code, "Unknown");
  }

  protected abstract static class AbstractPacketHeader extends Header {

    public static final int ICMP_HEADER_LENGTH = 4;

    protected IcmpTypeAndCode typeAndCode;
    protected short checksum;

    @SuppressWarnings("TypeParameterUnusedInFormals")
    @Override
    public abstract <T extends NamedNumber> T payloadType();

    @Override
    public int length() {
      return ICMP_HEADER_LENGTH;
    }

    @Override
    public Memory buffer() {
      if (buffer == null) {
        buffer = ALLOCATOR.allocate(length());
        buffer.writeByte(typeAndCode.type());
        buffer.writeByte(typeAndCode.code());
        buffer.writeShort(checksum);
      }
      return buffer;
    }
  }

  protected abstract static class AbstractPacketBuilder extends Builder {

    protected IcmpTypeAndCode typeAndCode = IcmpTypeAndCode.ROUTER_SOLICICATION;
    protected short checksum;

    public AbstractPacketBuilder typeAndCode(IcmpTypeAndCode typeAndCode) {
      this.typeAndCode = typeAndCode;
      return this;
    }

    public AbstractPacketBuilder checksum(short checksum) {
      this.checksum = checksum;
      return this;
    }
  }

  public static class IcmpTypeAndCode extends NamedNumber<Byte, IcmpTypeAndCode> {

    protected static final Collection<Icmp.IcmpTypeAndCode> ICMP4_REGISTRY =
            new HashSet<IcmpTypeAndCode>();

    protected static final Collection<Icmp.IcmpTypeAndCode> ICMP6_REGISTRY =
            new HashSet<Icmp.IcmpTypeAndCode>();

    public static final IcmpTypeAndCode NEIGHBOR_SOLICITATION =
        new IcmpTypeAndCode((byte) 0x87, (byte) 0x0, "Neighbor Solicitation");

    public static final IcmpTypeAndCode NEIGHBOR_ADVERTISEMENT =
        new IcmpTypeAndCode((byte) 0x88, (byte) 0x0, "Neighbor Advertisement");

    public static final IcmpTypeAndCode ROUTER_SOLICICATION =
        new IcmpTypeAndCode((byte) 0x85, (byte) 0x0, "Router Solicitation");

    public static final IcmpTypeAndCode ROUTER_ADVERTISEMENT =
        new IcmpTypeAndCode((byte) 0x86, (byte) 0x0, "Router Advertisement");

    public static final IcmpTypeAndCode REDIRECT =
        new IcmpTypeAndCode((byte) 0x89, (byte) 0x0, "Redirect");

    public static final IcmpTypeAndCode UNKNOWN =
        new IcmpTypeAndCode((byte) -1, (byte) -1, "Unknown");

    private static Map<Byte, IcmpTypeAndCode> REGISTRY = new HashMap<Byte, IcmpTypeAndCode>();

    private static Map<Byte, Builder> BUILDER = new HashMap<Byte, Builder>();

    private final byte type;
    private final byte code;
    private final String name;

    public IcmpTypeAndCode(byte type, byte code, String name) {
      super(type, name);
      this.type = type;
      this.code = code;
      this.name = name;
    }

    public byte type() {
      return type;
    }

    public byte code() {
      return code;
    }

    public String name() {
      return name;
    }

    @Override
    public String toString() {
      return new StringBuilder("IcmpTypeAndCode{")
          .append("type=")
          .append(type)
          .append(", code=")
          .append(code)
          .append(", name='")
          .append(name)
          .append('\'')
          .append('}')
          .toString();
    }

    public Packet newInstance(Memory buffer) {
      Builder packetBuilder = BUILDER.get(this.value());
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
     * @return returns {@link IcmpTypeAndCode} object.
     */
    public static IcmpTypeAndCode valueOf(final Byte value) {
      IcmpTypeAndCode icmpTypeAndCode = REGISTRY.get(value);
      if (icmpTypeAndCode == null) {
        return UNKNOWN;
      } else {
        return icmpTypeAndCode;
      }
    }

    /** @param type type */
    public static void register(final IcmpTypeAndCode type) {
      REGISTRY.put(type.value(), type);
    }

    /**
     * @param type type.
     * @param packetBuilder packet builder.
     */
    public static void register(IcmpTypeAndCode type, Builder packetBuilder) {
      BUILDER.put(type.value(), packetBuilder);
    }

    static {
      REGISTRY.put(ROUTER_SOLICICATION.value(), ROUTER_SOLICICATION);
      REGISTRY.put(ROUTER_ADVERTISEMENT.value(), ROUTER_ADVERTISEMENT);
      REGISTRY.put(NEIGHBOR_SOLICITATION.value(), NEIGHBOR_SOLICITATION);
      REGISTRY.put(NEIGHBOR_ADVERTISEMENT.value(), NEIGHBOR_ADVERTISEMENT);
      REGISTRY.put(REDIRECT.value(), REDIRECT);
      IcmpTypeAndCode.register(
          IcmpTypeAndCode.NEIGHBOR_SOLICITATION, new NeighborSolicitation.Builder());
      IcmpTypeAndCode.register(
          IcmpTypeAndCode.NEIGHBOR_ADVERTISEMENT, new NeighborAdvertisement.Builder());
      IcmpTypeAndCode.register(
          IcmpTypeAndCode.ROUTER_SOLICICATION, new RouterSolicitation.Builder());
      IcmpTypeAndCode.register(
          IcmpTypeAndCode.ROUTER_ADVERTISEMENT, new RouterAdvertisement.Builder());
      IcmpTypeAndCode.register(IcmpTypeAndCode.REDIRECT, new Redirect.Builder());
    }
  }
}
