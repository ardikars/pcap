package pcap.codec.udp;

import java.net.Inet4Address;
import java.net.InetAddress;
import pcap.codec.AbstractPacket;
import pcap.common.util.Strings;
import pcap.common.util.Validate;
import pcap.spi.PacketBuffer;
import pcap.spi.annotation.Incubating;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
@Incubating
public final class Udp extends AbstractPacket {

  public static final int TYPE = 17;

  private final long sourcePort;
  private final long destinationPort;
  private final long length;
  private final long checksum;

  private Udp(PacketBuffer buffer) {
    super(buffer);
    this.sourcePort = offset;
    this.destinationPort = sourcePort + 2;
    this.length = destinationPort + 2;
    this.checksum = length + 2;
  }

  public static Udp newInstance(int size, PacketBuffer buffer) {
    Validate.notIllegalArgument(
        size >= 8 && size <= 65535 && buffer.readableBytes() >= 8,
        "buffer size is not sufficient.");
    return new Udp(buffer);
  }

  public int sourcePort() {
    return buffer.getShort(sourcePort) & 0xFFFF;
  }

  public Udp sourcePort(int value) {
    buffer.setShort(sourcePort, value & 0xFFFF);
    return this;
  }

  public int destinationPort() {
    return buffer.getShort(destinationPort) & 0xFFFF;
  }

  public Udp destinationPort(int value) {
    buffer.setShort(destinationPort, value & 0xFFFF);
    return this;
  }

  public int length() {
    return buffer.getShort(length) & 0xFFFF;
  }

  public Udp length(int value) {
    buffer.setShort(length, value & 0xFFFF);
    return this;
  }

  public int checksum() {
    return buffer.getShort(checksum) & 0xFFFF;
  }

  public Udp checksum(int value) {
    buffer.setShort(checksum, value & 0xFFFF);
    return this;
  }

  public int calculateChecksum(InetAddress srcAddr, InetAddress dstAddr) {
    return Checksum.calculate(buffer, offset, srcAddr, dstAddr, TYPE, size(), length() - size());
  }

  public boolean isValidChecksum(Inet4Address src, Inet4Address dst) {
    return calculateChecksum(src, dst) == 0;
  }

  @Override
  public int size() {
    return 8;
  }

  @Override
  public String toString() {
    return Strings.toStringBuilder(this)
        .add("sourcePort", sourcePort())
        .add("destinationPort", destinationPort())
        .add("length", length())
        .add("checksum", "0x" + Integer.toHexString(checksum()))
        .toString();
  }
}
