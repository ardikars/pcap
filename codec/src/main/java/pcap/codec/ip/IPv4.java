package pcap.codec.ip;

import java.net.Inet4Address;
import java.util.Arrays;
import pcap.common.net.InetAddresses;
import pcap.common.util.Strings;
import pcap.spi.Packet;
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
public class IPv4 extends Packet.Abstract {

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

  public IPv4(PacketBuffer buffer) {
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
  }

  private static short calculateChecksum(PacketBuffer buffer, int headerLength, long offset) {
    long index = offset;
    int accumulation = 0;
    for (long i = 0; i < headerLength * 2; ++i) {
      if (i == 5) {
        accumulation += 0;
      } else {
        accumulation += 0xFFFF & buffer.getShort(index);
      }
      index += 2;
    }
    accumulation = (accumulation >> 16 & 0xFFFF) + (accumulation & 0xFFFF);
    return (short) (~accumulation & 0xFFFF);
  }

  public int version() {
    return (buffer.getByte(version) >> 4) & 0xF;
  }

  public IPv4 version(int value) {
    buffer.setByte(version, (value & 0xF) << 4 | ihl() & 0xF);
    return this;
  }

  public int ihl() {
    return buffer.getByte(version) & 0xF;
  }

  public IPv4 ihl(int value) {
    buffer.setByte(version, (version() & 0xF) << 4 | value & 0xF);
    return this;
  }

  public int dscp() {
    return (buffer.getByte(dscp) >> 2) & 0x3F;
  }

  public IPv4 dscp(int value) {
    buffer.setByte(dscp, ((value << 2) & 0x3F) | (ecn() & 0x3));
    return this;
  }

  public int ecn() {
    return buffer.getByte(dscp) & 0x3;
  }

  public IPv4 ecn(int value) {
    buffer.setByte(dscp, ((dscp() << 2) & 0x3F) | (value & 0x3));
    return this;
  }

  public int totalLength() {
    return buffer.getShortRE(totalLength) & 0xFFFF;
  }

  public IPv4 totalLength(int value) {
    buffer.setShortRE(totalLength, value & 0xFFFF);
    return this;
  }

  public int identification() {
    return buffer.getShortRE(identification) & 0xFFFF;
  }

  public IPv4 identification(int value) {
    buffer.setShortRE(identification, value & 0xFFFF);
    return this;
  }

  public int flags() {
    return (buffer.getShortRE(flags) >> 13) & 0x7;
  }

  public IPv4 flags(int value) {
    buffer.setShortRE(flags, (value & 0x7) << 13 | fragmentOffset() & 0x1FFF);
    return this;
  }

  public int fragmentOffset() {
    return buffer.getShortRE(flags) & 0x1FFF;
  }

  public IPv4 fragmentOffset(int value) {
    buffer.setShortRE(flags, (flags() & 0x7) << 13 | value & 0x1FFF);
    return this;
  }

  public int ttl() {
    return buffer.getByte(ttl) & 0xFFFF;
  }

  public IPv4 ttl(int value) {
    buffer.setByte(ttl, value & 0xFFFF);
    return this;
  }

  public int protocol() {
    return buffer.getByte(protocol) & 0xFFFF;
  }

  public IPv4 protocol(int value) {
    buffer.setByte(protocol, value & 0xFFFF);
    return this;
  }

  public int checksum() {
    return buffer.getShortRE(headerChecksum) & 0xFFFF;
  }

  public IPv4 checksum(int value) {
    buffer.setShortRE(headerChecksum, value & 0xFFFF);
    return this;
  }

  public int calculateChecksum() {
    return calculateChecksum(buffer, ihl(), offset);
  }

  public Inet4Address source() {
    return getInet4Address(source);
  }

  public IPv4 source(Inet4Address address) {
    buffer.setBytes(source, address.getAddress());
    return this;
  }

  public Inet4Address destination() {
    return getInet4Address(destination);
  }

  public IPv4 destination(Inet4Address address) {
    buffer.setBytes(destination, address.getAddress());
    return this;
  }

  public byte[] options() {
    byte[] data = new byte[(ihl() - 5) << 2];
    buffer.getBytes(options, data);
    return data;
  }

  public IPv4 options(byte[] value) {
    buffer.setBytes(options, value, 0, (ihl() - 5) << 2);
    return this;
  }

  private Inet4Address getInet4Address(long offset) {
    byte[] address = new byte[4];
    buffer.getBytes(offset, address);
    return InetAddresses.fromBytesToInet4Address(address);
  }

  @Override
  public int size() {
    if (!buffer.isReadable()) {
      throw new IllegalStateException("buffer is not readable.");
    }
    return buffer.getByte(buffer.readerIndex()) & 0xF;
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
        .add("checksum", checksum())
        .add("source", source().getHostAddress())
        .add("destination", destination().getHostAddress())
        .add("options", Arrays.toString(options()))
        .toString();
  }
}
