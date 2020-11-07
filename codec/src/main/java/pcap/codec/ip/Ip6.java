package pcap.codec.ip;

import pcap.codec.AbstractPacket;
import pcap.common.net.InetAddresses;
import pcap.common.util.Strings;
import pcap.common.util.Validate;
import pcap.spi.PacketBuffer;
import pcap.spi.annotation.Incubating;

import java.net.Inet6Address;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
@Incubating
public final class Ip6 extends AbstractPacket {

  public static final int TYPE = 0x86dd;

  private final long version;
  private final long payloadLength;
  private final long nextHeader;
  private final long hopLimit;
  private final long source;
  private final long destination;

  private Ip6(PacketBuffer buffer) {
    super(buffer);
    this.version = offset;
    this.payloadLength = version + 4;
    this.nextHeader = payloadLength + 2;
    this.hopLimit = nextHeader + 1;
    this.source = hopLimit + 1;
    this.destination = source + 16;
  }

  public static Ip6 newInstance(int size, PacketBuffer buffer) {
    Validate.notIllegalArgument(
        size == 40 && buffer.readableBytes() >= 40, "buffer size is not sufficient.");
    return new Ip6(buffer);
  }

  public int version() {
    return (buffer.getInt(version) >> 28) & 0xF;
  }

  public Ip6 version(int value) {
    buffer.setInt(
        version, (value & 0xF) << 28 | (trafficClass() & 0xFF) << 20 | flowLabel() & 0xFFFFF);
    return this;
  }

  public int trafficClass() {
    return (buffer.getInt(version) >> 20) & 0xFF;
  }

  public Ip6 trafficClass(int value) {
    buffer.setInt(version, (version() & 0xF) << 28 | (value & 0xFF) << 20 | flowLabel() & 0xFFFFF);
    return this;
  }

  public int flowLabel() {
    return (buffer.getInt(version) & 0xFFFFF);
  }

  public Ip6 flowLabel(int value) {
    buffer.setInt(
        version, (version() & 0xF) << 28 | (trafficClass() & 0xFF) << 20 | value & 0xFFFFF);
    return this;
  }

  public int payloadLength() {
    return buffer.getShort(payloadLength) & 0xFFFF;
  }

  public Ip6 payloadLength(int value) {
    buffer.setShort(payloadLength, value & 0xFFFF);
    return this;
  }

  public int nextHeader() {
    return buffer.getByte(nextHeader) & 0xFF;
  }

  public Ip6 nextHeader(int value) {
    buffer.setByte(nextHeader, value & 0xFF);
    return this;
  }

  public int hopLimit() {
    return buffer.getByte(hopLimit) & 0xFF;
  }

  public Ip6 hopLimit(int value) {
    buffer.setByte(hopLimit, value & 0xFF);
    return this;
  }

  public Inet6Address source() {
    return getInet6Address(source);
  }

  public Ip6 source(Inet6Address value) {
    buffer.setBytes(source, value.getAddress());
    return this;
  }

  public Inet6Address destination() {
    return getInet6Address(destination);
  }

  public Ip6 destination(Inet6Address value) {
    buffer.setBytes(destination, value.getAddress());
    return this;
  }

  private Inet6Address getInet6Address(long offset) {
    byte[] address = new byte[16];
    buffer.getBytes(offset, address);
    return InetAddresses.fromBytesToInet6Address(address);
  }

  @Override
  public int size() {
    return 40;
  }

  @Override
  public String toString() {
    return Strings.toStringBuilder(this)
        .add("version", version())
        .add("trafficClass", trafficClass())
        .add("flowLabel", flowLabel())
        .add("payloadLength", payloadLength())
        .add("nextHeader", nextHeader())
        .add("hopLimit", hopLimit())
        .add("source", source().getHostAddress())
        .add("destination", destination().getHostAddress())
        .toString();
  }
}
