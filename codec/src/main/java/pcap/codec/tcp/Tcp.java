/** This code is licenced under the GPL version 2. */
package pcap.codec.tcp;

import java.util.Arrays;
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
public class Tcp extends AbstractPacket {

  private final Header header;
  private final Packet payload;
  private final Builder builder;

  private Tcp(final Builder builder) {
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

  public static Tcp newPacket(Memory buffer) {
    return new Tcp.Builder().build(buffer);
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
    return Strings.toStringBuilder(this).add("header", header).add("payload", payload).toString();
  }

  public static final class Header extends AbstractPacket.Header {

    public static final int TCP_HEADER_LENGTH = 20;

    private final short sourcePort;
    private final short destinationPort;
    private final int sequence;
    private final int acknowledge;
    private final byte dataOffset;
    private final TcpFlags flags;
    private final short windowSize;
    private final short checksum;
    private final short urgentPointer;
    private final byte[] options;

    private final Builder builder;

    private Header(final Builder builder) {
      this.sourcePort = builder.sourcePort;
      this.destinationPort = builder.destinationPort;
      this.sequence = builder.sequence;
      this.acknowledge = builder.acknowledge;
      this.dataOffset = builder.dataOffset;
      this.flags = builder.flags;
      this.windowSize = builder.windowSize;
      this.checksum = builder.checksum;
      this.urgentPointer = builder.urgentPointer;
      this.options = builder.options;
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
      buf.writeByte(TransportLayer.TCP.value());
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

    /**
     * Source port.
     *
     * @return returns source port.
     */
    public int sourcePort() {
      return sourcePort & 0xffff;
    }

    /**
     * Destination port.
     *
     * @return returns destination port.
     */
    public int destinationPort() {
      return destinationPort & 0xffff;
    }

    /**
     * Sequence number.
     *
     * @return sequence number.
     */
    public int sequence() {
      return sequence;
    }

    /**
     * Acknowledge.
     *
     * @return returns acknowledge.
     */
    public int acknowledge() {
      return acknowledge;
    }

    /**
     * Data offset.
     *
     * @return returns data offset.
     */
    public int dataOffset() {
      return dataOffset & 0xf;
    }

    /**
     * Tcp flags.
     *
     * @return returns {@link TcpFlags}.
     */
    public TcpFlags flags() {
      return flags;
    }

    /**
     * Windows size.
     *
     * @return returns windows size.
     */
    public int windowSize() {
      return windowSize & 0xffff;
    }

    /**
     * Checksum.
     *
     * @return returns checksum.
     */
    public int checksum() {
      return checksum & 0xffff;
    }

    /**
     * Urgent pointer.
     *
     * @return urgent pointer.
     */
    public int urgentPointer() {
      return urgentPointer & 0xffff;
    }

    /**
     * Get options.
     *
     * @return returns options.
     */
    public byte[] options() {
      if (options == null) {
        return new byte[0];
      }
      byte[] buffer = new byte[this.options.length];
      System.arraycopy(options, 0, buffer, 0, buffer.length);
      return buffer;
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
      int length = TCP_HEADER_LENGTH;
      if (this.options != null) {
        length += this.options.length;
      }
      return length;
    }

    @Override
    public Memory buffer() {
      if (buffer == null) {
        buffer = ALLOCATOR.allocate(length());
        buffer.writeShort(this.sourcePort);
        buffer.writeShort(this.destinationPort);
        buffer.writeInt(this.sequence);
        buffer.writeInt(this.acknowledge);
        buffer.writeShort((this.flags.value() & 0x1ff) | (this.dataOffset & 0xf) << 12);
        buffer.writeShort(this.windowSize);
        buffer.writeShort(this.checksum);
        buffer.writeShort(this.urgentPointer);
        if (this.options != null) {
          buffer.writeBytes(this.options);
        }
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
          && sequence == header.sequence
          && acknowledge == header.acknowledge
          && dataOffset == header.dataOffset
          && windowSize == header.windowSize
          && checksum == header.checksum
          && urgentPointer == header.urgentPointer
          && flags.equals(header.flags)
          && Arrays.equals(options, header.options);
    }

    @Override
    public int hashCode() {
      int result =
          Objects.hash(
              sourcePort,
              destinationPort,
              sequence,
              acknowledge,
              dataOffset,
              flags,
              windowSize,
              checksum,
              urgentPointer);
      result = 31 * result + Arrays.hashCode(options);
      return result;
    }

    @Override
    public String toString() {
      return Strings.toStringBuilder(this)
          .add("sourcePort", sourcePort & 0xFFFF)
          .add("destinationPort", destinationPort & 0xFFFF)
          .add("sequence", (sequence & 0xFFFFFFFFL))
          .add("acknowledge", (acknowledge & 0xFFFFFFFFL))
          .add("dataOffset", dataOffset & 0xFF)
          .add("flags", flags)
          .add("windowSize", windowSize & 0xFFFF)
          .add("checksum", checksum & 0xFFFF)
          .add("urgentPointer", urgentPointer & 0xFF)
          .add("options", options == null || options.length == 0 ? "(None)" : Strings.hex(options))
          .toString();
    }
  }

  public static class Builder extends AbstractPacket.Builder {

    private short sourcePort;
    private short destinationPort;
    private int sequence;
    private int acknowledge;
    private byte dataOffset;
    private TcpFlags flags;
    private short windowSize;
    private short checksum;
    private short urgentPointer;
    private byte[] options;

    private Memory buffer;
    private Memory payloadBuffer;

    /** A helper field. */
    private boolean calculateChecksum;

    private InetAddress srcAddr;
    private InetAddress dstAddr;

    /**
     * Source port.
     *
     * @param sourcePort source port.
     * @return returns this {@link Builder}.
     */
    public Builder sourcePort(int sourcePort) {
      this.sourcePort = (short) (sourcePort & 0xffff);
      return this;
    }

    /**
     * Destination port.
     *
     * @param destinationPort destination port.
     * @return returns this {@link Builder}.
     */
    public Builder destinationPort(int destinationPort) {
      this.destinationPort = (short) (destinationPort & 0xffff);
      return this;
    }

    /**
     * Sequence number.
     *
     * @param sequence sequence number,
     * @return returns this {@link Builder}.
     */
    public Builder sequence(int sequence) {
      this.sequence = sequence;
      return this;
    }

    /**
     * Acknowledge.
     *
     * @param acknowledge acknowledge.
     * @return returns this {@link Builder}.
     */
    public Builder acknowledge(int acknowledge) {
      this.acknowledge = acknowledge;
      return this;
    }

    /**
     * Data offset.
     *
     * @param dataOffset data offset.
     * @return returns this {@link Builder}.
     */
    public Builder dataOffset(int dataOffset) {
      this.dataOffset = (byte) (dataOffset & 0xf);
      return this;
    }

    /**
     * Flags.
     *
     * @param flags flags.
     * @return returns this {@link Builder}.
     */
    public Builder flags(TcpFlags flags) {
      this.flags = flags;
      return this;
    }

    /**
     * Windows size.
     *
     * @param windowSize window size.
     * @return returns this {@link Builder}.
     */
    public Builder windowsSize(int windowSize) {
      this.windowSize = (short) (windowSize & 0xffff);
      return this;
    }

    /**
     * Checksum.
     *
     * @param checksum cheksum.
     * @return returns this {@link Builder}.
     */
    public Builder checksum(int checksum) {
      this.checksum = (short) (checksum & 0xffff);
      return this;
    }

    /**
     * Urgent pointer.
     *
     * @param urgentPointer urgent pointer.
     * @return returns this {@link Builder}.
     */
    public Builder urgentPointer(int urgentPointer) {
      this.urgentPointer = (short) (urgentPointer & 0xffff);
      return this;
    }

    /**
     * Options.
     *
     * @param options options.
     * @return returns this {@link Builder}.
     */
    public Builder options(byte[] options) {
      this.options = Validate.nullPointerThenReturns(options, new byte[0]);
      this.dataOffset = (byte) (20 + options.length + 3 >> 2);
      return this;
    }

    @Override
    public Builder payload(AbstractPacket packet) {
      this.payloadBuffer = packet.buffer();
      return this;
    }

    /**
     * Calculate checksum.
     *
     * @param srcAddr source ip address (pseudo header).
     * @param dstAddr destination ip address (pseudo header).
     * @param calculateChecksum true for calculating checksum, false otherwise.
     * @return returns this {@link Builder}.
     */
    public Builder calculateChecksum(
        InetAddress srcAddr, InetAddress dstAddr, boolean calculateChecksum) {
      this.srcAddr = srcAddr;
      this.dstAddr = dstAddr;
      this.calculateChecksum = calculateChecksum;
      return this;
    }

    @Override
    public Tcp build() {
      if (calculateChecksum && srcAddr != null && dstAddr != null) {
        if (buffer == null) {
          final Tcp tcp = new Tcp(this);
          int length =
              tcp.header.length()
                  + (this.payloadBuffer == null ? 0 : this.payloadBuffer.capacity());
          this.buffer = ALLOCATOR.allocate(length);
          this.buffer.writeBytes(tcp.header().buffer(), 0, tcp.header().length());
          if (this.payloadBuffer != null) {
            this.buffer.writeBytes(payloadBuffer, 0, this.payloadBuffer.capacity());
          }
        }
        checksum(Tcp.Header.calculateChecksum(buffer, srcAddr, dstAddr));
        buffer.setShort(16, this.checksum);
      }
      return new Tcp(this);
    }

    @Override
    public Tcp build(Memory buffer) {
      resetIndex(buffer);
      this.sourcePort = buffer.readShort();
      this.destinationPort = buffer.readShort();
      this.sequence = buffer.readInt();
      this.acknowledge = buffer.readInt();
      short tmp = buffer.readShort();
      this.dataOffset = (byte) (tmp >> 12 & 0xf);
      this.flags = new TcpFlags.Builder().build((short) (tmp & 0x1ff));
      this.windowSize = buffer.readShort();
      this.checksum = buffer.readShort();
      this.urgentPointer = buffer.readShort();
      if (this.dataOffset > 5 && buffer.readableBytes() > 0) {
        int optionLength = (this.dataOffset << 2) - Header.TCP_HEADER_LENGTH;
        if (buffer.capacity() < Header.TCP_HEADER_LENGTH + optionLength) {
          optionLength = buffer.capacity() - Header.TCP_HEADER_LENGTH;
        }
        this.options = new byte[optionLength];
        buffer.readBytes(options);
        int length = 20 + optionLength;
        this.payloadBuffer = buffer.slice(length, buffer.capacity() - length);
      } else {
        this.options = new byte[0];
      }
      this.buffer = buffer;
      this.payloadBuffer = buffer.slice();
      return new Tcp(this);
    }

    @Override
    public Builder reset() {
      return reset(readerIndex, Header.TCP_HEADER_LENGTH);
    }

    @Override
    public Builder reset(int offset, int length) {
      if (buffer != null) {
        resetIndex(buffer);
        Validate.notIllegalArgument(offset + length <= buffer.capacity());
        Validate.notIllegalArgument((sourcePort & 0xFFFF) >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument((destinationPort & 0xFFFF) >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument((sequence & 0xFFFFFFFFL) >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument((acknowledge & 0xFFFFFFFFL) >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(flags != null, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument((windowSize & 0xFFFF) >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument((checksum & 0xFFFF) >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument((urgentPointer & 0xFFFF) >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument((dataOffset & 0xF) >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(options != null, ILLEGAL_HEADER_EXCEPTION);
        int index = offset;
        buffer.setShort(index, sourcePort);
        index += 2;
        buffer.setShort(index, destinationPort);
        index += 2;
        buffer.setInt(index, sequence);
        index += 4;
        buffer.setInt(index, acknowledge);
        index += 4;
        int tmp = flags.value() & 0x1FF | (dataOffset << 12);
        buffer.setShort(index, tmp);
        index += 2;
        buffer.setShort(index, windowSize);
        index += 2;
        buffer.setShort(index, checksum);
        index += 2;
        buffer.setShort(index, urgentPointer);
        index += 2;
        if (dataOffset > 5 && options != null) {
          buffer.setBytes(index, options);
        }
      }
      return this;
    }
  }
}
