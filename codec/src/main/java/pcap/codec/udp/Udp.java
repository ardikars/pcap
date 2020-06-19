/** This code is licenced under the GPL version 2. */
package pcap.codec.udp;

import java.util.Objects;
import pcap.codec.AbstractPacket;
import pcap.codec.ApplicationLayer;
import pcap.codec.Packet;
import pcap.codec.TransportLayer;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;
import pcap.common.net.Inet4Address;
import pcap.common.net.Inet6Address;
import pcap.common.net.InetAddress;
import pcap.common.util.Strings;
import pcap.common.util.Validate;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class Udp extends AbstractPacket {

  private final Header header;
  private final Packet payload;
  private final Builder builder;

  private Udp(final Builder builder) {
    this.header = new Header(builder);
    this.payloadBuffer = builder.payloadBuffer;
    if (this.payloadBuffer != null
        && this.payloadBuffer.readerIndex() < this.payloadBuffer.writerIndex()) {
      this.payload =
          ApplicationLayer.valueOf(this.header.payloadType().value())
              .newInstance(this.payloadBuffer);
    } else {
      this.payload = null;
    }
    this.builder = builder;
  }

  public static Udp newPacket(Memory buffer) {
    return new Udp.Builder().build(buffer);
  }

  @Override
  public Header header() {
    return header;
  }

  @Override
  public Packet payload() {
    return payload;
  }

  @Override
  public Builder builder() {
    return builder;
  }

  @Override
  public Memory buffer() {
    return header().buffer();
  }

  @Override
  public String toString() {
    return Strings.toStringBuilder(this)
        .add("header", header)
        .add("payload", payload != null ? payload.getClass().getSimpleName() : "(None)")
        .toString();
  }

  public static class Header extends AbstractPacket.Header {

    public static final int UDP_HEADER_LENGTH = 8;

    private final short sourcePort;
    private final short destinationPort;
    private final short length;
    private final short checksum;

    private final Builder builder;

    private Header(final Builder builder) {
      this.sourcePort = builder.sourcePort;
      this.destinationPort = builder.destinationPort;
      this.length = builder.length;
      this.checksum = builder.checksum;
      this.buffer = resetIndex(builder.buffer, length());
      this.builder = builder;
    }

    static short calculateChecksum(Memory buffer, InetAddress srcAddr, InetAddress dstAddr) {
      int length = buffer.capacity();
      Memory buf;
      int pseudoSize;
      if (srcAddr instanceof Inet4Address && dstAddr instanceof Inet4Address) {
        pseudoSize = 12;
      } else if (srcAddr instanceof Inet6Address && dstAddr instanceof Inet6Address) {
        pseudoSize = 40;
      } else {
        return 0;
      }

      buf = ALLOCATOR.allocate(length + pseudoSize + (length % 2 == 0 ? 0 : 1));
      buf.writeBytes(buffer, 0, buffer.capacity());
      buf.writeByte(0);

      buf.writeBytes(srcAddr.address());
      buf.writeBytes(dstAddr.address());
      buf.writeByte(0);
      buf.writeByte(TransportLayer.UDP.value());
      if (srcAddr instanceof Inet4Address && dstAddr instanceof Inet4Address) {
        buf.writeShort(length);
      } else if (srcAddr instanceof Inet6Address && dstAddr instanceof Inet6Address) {
        buf.writeInt(length);
      }

      int accumulation = 0;
      while (buf.readableBytes() > 1) {
        accumulation += buf.readShort() & 0xFFFF;
      }

      buf.release();

      accumulation = (accumulation >> 16 & 0xFFFF) + (accumulation & 0xFFFF);
      return (short) (~accumulation & 0xFFFF);
    }

    public int sourcePort() {
      return sourcePort & 0xffff;
    }

    public int destinationPort() {
      return destinationPort & 0xffff;
    }

    public int lengthUdp() {
      return length & 0xFFFF;
    }

    public int checksum() {
      return checksum & 0xffff;
    }

    /**
     * Check whether checksum is valid.
     *
     * @param srcAddr source ip pseudo header.
     * @param dstAddr destination ip pseudo header.
     * @return returns true if checksum is valid, false otherwise.
     */
    public boolean isValidChecksum(InetAddress srcAddr, InetAddress dstAddr) {
      Memory buf =
          ALLOCATOR.allocate(
              length() + (builder.payloadBuffer == null ? 0 : builder.payloadBuffer.capacity()));
      buf.writeBytes(buffer, 0, length());
      buf.writeBytes(builder.payloadBuffer, 0, builder.payloadBuffer.capacity());
      boolean valid = 0 == calculateChecksum(buf, srcAddr, dstAddr);
      buf.release();
      return valid;
    }

    @Override
    public ApplicationLayer payloadType() {
      return ApplicationLayer.valueOf(destinationPort);
    }

    @Override
    public int length() {
      return UDP_HEADER_LENGTH;
    }

    @Override
    public Memory buffer() {
      if (buffer == null) {
        buffer = ALLOCATOR.allocate(length());
        buffer.writeShort(this.sourcePort & 0xFFFF);
        buffer.writeShort(this.destinationPort & 0xFFFF);
        buffer.writeShort(this.length & 0xFFFF);
        buffer.writeShort(this.checksum & 0xFFFF);
      }
      return buffer;
    }

    @Override
    public Builder builder() {
      return builder;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;
      Header header = (Header) o;
      return sourcePort == header.sourcePort
          && destinationPort == header.destinationPort
          && length == header.length
          && checksum == header.checksum;
    }

    @Override
    public int hashCode() {
      return Objects.hash(sourcePort, destinationPort, length, checksum);
    }

    @Override
    public String toString() {
      return Strings.toStringBuilder(this)
          .add("sourcePort", sourcePort & 0xFFFF)
          .add("destinationPort", destinationPort & 0xFFFF)
          .add("length", length & 0xFFFF)
          .add("checksum", checksum & 0xFFFF)
          .toString();
    }
  }

  public static class Builder extends AbstractPacket.Builder {

    private short sourcePort;
    private short destinationPort;
    private short length;
    private short checksum;

    private Memory buffer;
    private Memory payloadBuffer;

    /** A helper field. */
    private boolean calculateChecksum;

    private InetAddress srcAddr;
    private InetAddress dstAddr;

    public Builder sourcePort(int sourcePort) {
      this.sourcePort = (short) (sourcePort & 0xffff);
      return this;
    }

    public Builder destinationPort(int destinationPort) {
      this.destinationPort = (short) (destinationPort & 0xffff);
      return this;
    }

    public Builder length(int length) {
      this.length = (short) (length & 0xffff);
      return this;
    }

    public Builder checksum(int checksum) {
      this.checksum = (short) (checksum & 0xffff);
      return this;
    }

    public Builder payload(Memory payload) {
      this.payloadBuffer = payload;
      return this;
    }

    public Builder calculateChecksum(
        InetAddress srcAddr, InetAddress dstAddr, boolean calculateChecksum) {
      this.srcAddr = srcAddr;
      this.dstAddr = dstAddr;
      this.calculateChecksum = calculateChecksum;
      return this;
    }

    @Override
    public Udp build() {
      if (calculateChecksum && srcAddr != null && dstAddr != null) {
        if (buffer == null) {
          final Udp udp = new Udp(this);
          int bufLen =
              udp.header.length()
                  + (this.payloadBuffer == null ? 0 : this.payloadBuffer.capacity());
          this.buffer = ALLOCATOR.allocate(bufLen);
          this.buffer.writeBytes(udp.header().buffer(), 0, udp.header().length());
          if (this.payloadBuffer != null) {
            this.buffer.writeBytes(payloadBuffer, 0, this.payloadBuffer.capacity());
          }
        }
        checksum(Udp.Header.calculateChecksum(buffer, srcAddr, dstAddr));
        buffer.setShort(6, this.checksum);
      }
      return new Udp(this);
    }

    @Override
    public Udp build(Memory buffer) {
      resetIndex(buffer);
      this.sourcePort = buffer.readShort();
      this.destinationPort = buffer.readShort();
      this.length = buffer.readShort();
      this.checksum = buffer.readShort();
      this.buffer = buffer;
      this.payloadBuffer = buffer.slice();
      return new Udp(this);
    }

    @Override
    public Builder reset() {
      return reset(readerIndex, Header.UDP_HEADER_LENGTH);
    }

    @Override
    public Builder reset(int offset, int length) {
      if (buffer != null) {
        Validate.notIllegalArgument(offset + length <= buffer.capacity());
        Validate.notIllegalArgument((this.sourcePort & 0xFFFF) >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument((this.destinationPort & 0xFFFF) >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument((this.length & 0xFFFF) >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument((this.checksum & 0xFFFF) >= 0, ILLEGAL_HEADER_EXCEPTION);
        int index = offset;
        buffer.setShort(index, sourcePort);
        index += 2;
        buffer.setShort(index, destinationPort);
        index += 2;
        buffer.setShort(index, this.length);
        index += 2;
        buffer.setShort(index, checksum);
      }
      return this;
    }
  }
}
