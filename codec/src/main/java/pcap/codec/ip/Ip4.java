package pcap.codec.ip;

import java.net.Inet4Address;
import pcap.codec.AbstractPacket;
import pcap.common.net.InetAddresses;
import pcap.common.util.Bytes;
import pcap.common.util.Strings;
import pcap.common.util.Validate;
import pcap.spi.PacketBuffer;
import pcap.spi.annotation.Incubating;

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Version|  IHL  |Type of Service|          Total Length         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Identification        |Flags|      Fragment Offset    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Time to Live |    Protocol   |         Header Checksum       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       Source Address                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Destination Address                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Options                    |    Padding    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
/**
 *
 *
 * <ul>
 *   <li>https://tools.ietf.org/html/rfc791
 *   <li>https://tools.ietf.org/html/rfc3168
 * </ul>
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
@Incubating
public final class Ip4 extends AbstractPacket {

  public static final int TYPE = 0x0800;

  private final long version;
  private final long dscp;
  private final long totalLength;
  private final long identification;
  private final long flags;
  private final long ttl;
  private final long protocol;
  private final long headerChecksum;
  private final long source;
  private final long destination;
  private final long options;

  private final int maxIhl;

  private Ip4(PacketBuffer buffer) {
    super(buffer);
    this.version = offset;
    this.dscp = version + 1;
    this.totalLength = dscp + 1;
    this.identification = totalLength + 2;
    this.flags = identification + 2;
    this.ttl = flags + 2;
    this.protocol = ttl + 1;
    this.headerChecksum = protocol + 1;
    this.source = headerChecksum + 2;
    this.destination = source + 4;
    this.options = destination + 4;
    this.maxIhl = ihl();
  }

  public static Ip4 newInstance(int size, PacketBuffer buffer) {
    Validate.notIllegalArgument(
        size >= 20 && size <= 60 && buffer.readableBytes() >= 20, "buffer size is not sufficient.");
    buffer.setByte(buffer.readerIndex(), (4 & 0xF) << 4 | (size >> 2) & 0xF);
    return new Ip4(buffer);
  }

  public int version() {
    return (buffer.getByte(version) >> 4) & 0xF;
  }

  public Ip4 version(int value) {
    buffer.setByte(version, (value & 0xF) << 4 | ihl() & 0xF);
    return this;
  }

  public int ihl() {
    return buffer.getByte(version) & 0xF;
  }

  public Ip4 ihl(int value) {
    if (value < 5 || value > maxIhl) {
      throw new IllegalArgumentException(
          String.format("value: %d (expected: 5 >= value <= %d)", value, maxIhl));
    }
    buffer.setByte(version, (version() & 0xF) << 4 | value & 0xF);
    return this;
  }

  public int dscp() {
    return (buffer.getByte(dscp) >> 2) & 0x3F;
  }

  public Ip4 dscp(int value) {
    buffer.setByte(dscp, ((value << 2) & 0x3F) | (ecn() & 0x3));
    return this;
  }

  public int ecn() {
    return buffer.getByte(dscp) & 0x3;
  }

  public Ip4 ecn(int value) {
    buffer.setByte(dscp, ((dscp() << 2) & 0x3F) | (value & 0x3));
    return this;
  }

  public int totalLength() {
    return buffer.getShort(totalLength) & 0xFFFF;
  }

  public Ip4 totalLength(int value) {
    buffer.setShort(totalLength, value & 0xFFFF);
    return this;
  }

  public int identification() {
    return buffer.getShort(identification) & 0xFFFF;
  }

  public Ip4 identification(int value) {
    buffer.setShort(identification, value & 0xFFFF);
    return this;
  }

  public int flags() {
    return (buffer.getShort(flags) >> 13) & 0x7;
  }

  public Ip4 flags(int value) {
    buffer.setShort(flags, (value & 0x7) << 13 | fragmentOffset() & 0x1FFF);
    return this;
  }

  public int fragmentOffset() {
    return buffer.getShort(flags) & 0x1FFF;
  }

  public Ip4 fragmentOffset(int value) {
    buffer.setShort(flags, (flags() & 0x7) << 13 | value & 0x1FFF);
    return this;
  }

  public int ttl() {
    return buffer.getByte(ttl) & 0xFFFF;
  }

  public Ip4 ttl(int value) {
    buffer.setByte(ttl, value & 0xFFFF);
    return this;
  }

  public int protocol() {
    return buffer.getByte(protocol) & 0xFF;
  }

  public Ip4 protocol(int value) {
    buffer.setByte(protocol, value & 0xFF);
    return this;
  }

  public int checksum() {
    return buffer.getShort(headerChecksum) & 0xFFFF;
  }

  public Ip4 checksum(int value) {
    buffer.setShort(headerChecksum, value & 0xFFFF);
    return this;
  }

  public int calculateChecksum() {
    int accumulation = Checksum.sum(buffer, offset, ihl() << 2);
    accumulation -= buffer.getShort(10) & 0xFFFF;
    accumulation = (accumulation >> 16 & 0xFFFF) + (accumulation & 0xFFFF);
    return (~accumulation & 0xFFFF);
  }

  public boolean isValidChecksum() {
    return checksum() == calculateChecksum();
  }

  public Inet4Address source() {
    return InetAddresses.fromBytesToInet4Address(Bytes.toByteArray(buffer.getInt(source)));
  }

  public Ip4 source(Inet4Address address) {
    buffer.setBytes(source, address.getAddress());
    return this;
  }

  public Inet4Address destination() {
    return InetAddresses.fromBytesToInet4Address(Bytes.toByteArray(buffer.getInt(destination)));
  }

  public Ip4 destination(Inet4Address address) {
    buffer.setBytes(destination, address.getAddress());
    return this;
  }

  public byte[] options() {
    byte[] data = new byte[(ihl() - 5) << 2];
    buffer.getBytes(options, data);
    return data;
  }

  public Ip4 options(byte[] value) {
    int maxLength = (ihl() - 5) << 2;
    buffer.setBytes(options, value, 0, Math.min(value.length, maxLength));
    return this;
  }

  @Override
  public int size() {
    if (maxIhl == 0) {
      Validate.notIllegalState(buffer.readableBytes() >= 20, "buffer size is not sufficient.");
      return (buffer.getByte(buffer.readerIndex()) & 0xF) << 2;
    }
    return (buffer.getByte(version) & 0xF) << 2;
  }

  @Override
  public String toString() {
    return Strings.toStringBuilder(this)
        .add("version", version())
        .add("ihl", ihl())
        .add("dscp", dscp())
        .add("ecn", ecn())
        .add("totalLength", totalLength())
        .add("identification", identification())
        .add("flags", flags())
        .add("fragmentOffset", fragmentOffset())
        .add("ttl", ttl())
        .add("protocol", protocol())
        .add("checksum", "0x" + Integer.toHexString(checksum()))
        .add("source", source().getHostAddress())
        .add("destination", destination().getHostAddress())
        .add("options", "0x" + Strings.hex(options()))
        .toString();
  }
}
