package pcap.codec.udp;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import pcap.common.util.Strings;
import pcap.common.util.Validate;
import pcap.spi.Packet;
import pcap.spi.PacketBuffer;
import pcap.spi.annotation.Incubating;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
@Incubating
public final class Udp extends Packet.Abstract {

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

  public int calculateChecksum(InetAddress srcAddr, InetAddress dstAddr, int payloadLength) {
    boolean isIp = srcAddr instanceof Inet4Address && dstAddr instanceof Inet4Address;
    int accumulation = 0;
    ByteBuffer bb = ByteBuffer.allocate(isIp ? 12 : 40);
    bb.put(srcAddr.getAddress());
    bb.put(dstAddr.getAddress());
    bb.put((byte) 0);
    bb.put((byte) TYPE);
    if (isIp) {
      bb.putShort((short) length());
    } else {
      bb.putInt(length());
    }
    bb.rewind();

    for (int i = 0; i < bb.capacity() / 2; ++i) {
      accumulation += bb.getShort() & 0xFFFF;
    }

    long offset = this.offset;
    long length =
        payloadLength % 2 == 0 ? payloadLength + this.size() : payloadLength + this.size() - 1;
    for (long i = offset; i < length; i += 2) {
      accumulation += this.buffer.getShort(i) & 0xFFFF;
    }
    if (payloadLength % 2 > 0) {
      accumulation += ((this.buffer.getByte(length)) & 0xFF) << 8;
    }

    accumulation = (accumulation >> 16 & 0xFFFF) + (accumulation & 0xFFFF);
    return (~accumulation & 0xFFFF);
  }

  public boolean isValidChecksum(Inet4Address src, Inet4Address dst, int payloadLength) {
    return calculateChecksum(src, dst, payloadLength) == 0;
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
