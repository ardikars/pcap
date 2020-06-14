/** This code is licenced under the GPL version 2. */
package pcap.codec.ip;

import pcap.codec.Packet;
import pcap.codec.TransportLayer;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;
import pcap.common.net.Inet4Address;
import pcap.common.util.Strings;
import pcap.common.util.Validate;

import java.util.Arrays;
import java.util.Objects;

/**
 * @see <a href="https://en.wikipedia.org/wiki/IPv4">Wikipedia</a>
 * @see <a href="https://tools.ietf.org/html/rfc791>RFC</a>
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
@Inclubating
public class Ip4 extends Ip {

  private final Header header;
  private final Packet payload;
  private final Builder builder;

  private Ip4(final Builder builder) {
    this.header = new Header(builder);
    this.payloadBuffer = builder.payloadBuffer;
    if (this.payloadBuffer != null
        && this.payloadBuffer.readerIndex() < this.payloadBuffer.writerIndex()) {
      this.payload =
          TransportLayer.valueOf(this.header.payloadType().value()).newInstance(this.payloadBuffer);
    } else {
      payload = null;
    }
    this.builder = builder;
  }

  public static final Ip4 newPacket(Memory buffer) {
    return new Builder().build(buffer);
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
        .add("header", header())
        .add("payload", payload() != null ? payload().getClass().getSimpleName() : "(None)")
        .toString();
  }

  public static final class Header extends AbstractPacketHeader {

    public static final int IPV4_HEADER_LENGTH = 20;

    private final byte headerLength;
    private final byte diffServ;
    private final byte expCon;
    private final short totalLength;
    private final short identification;
    private final byte flags;
    private final short fragmentOffset;
    private final byte ttl;
    private final TransportLayer protocol;
    private final short checksum;
    private final Inet4Address sourceAddress;
    private final Inet4Address destinationAddress;
    private final byte[] options;

    private final Builder builder;

    protected Header(final Builder builder) {
      super((byte) 0x04);
      this.headerLength = builder.headerLength;
      this.diffServ = builder.diffServ;
      this.expCon = builder.expCon;
      this.totalLength = builder.totalLength;
      this.identification = builder.identification;
      this.flags = builder.flags;
      this.fragmentOffset = builder.fragmentOffset;
      this.ttl = builder.ttl;
      this.protocol = builder.protocol;
      this.checksum = builder.checksum;
      this.sourceAddress = builder.sourceAddress;
      this.destinationAddress = builder.destinationAddress;
      this.options = builder.options;
      this.buffer = resetIndex(builder.buffer, length());
      this.builder = builder;
    }

    private static short calculateChecksum(Memory buffer, int headerLength, int offset) {
      int index = offset;
      int accumulation = 0;
      for (int i = 0; i < headerLength * 2; ++i) {
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

    public int headerLength() {
      return headerLength & 0xF;
    }

    public int diffServ() {
      return diffServ & 0x3F;
    }

    public int expCon() {
      return expCon & 0x3;
    }

    public int totalLength() {
      return totalLength & 0xFFFF;
    }

    public int identification() {
      return identification & 0xFFFF;
    }

    public int flags() {
      return flags & 0x7;
    }

    public int fragmentOffset() {
      return fragmentOffset & 0x1FFF;
    }

    public int ttl() {
      return ttl & 0xFF;
    }

    public TransportLayer protocol() {
      return protocol;
    }

    public int checksum() {
      return checksum & 0xFFFF;
    }

    public Inet4Address sourceAddress() {
      return sourceAddress;
    }

    public Inet4Address destinationAddress() {
      return destinationAddress;
    }

    /**
     * Get options.
     *
     * @return returns options.
     */
    public byte[] options() {
      byte[] options = new byte[this.options.length];
      System.arraycopy(this.options, 0, options, 0, options.length);
      return options;
    }

    /**
     * Check whether checksum is valid.
     *
     * @return returns true if checksum is valid, false otherwise.
     */
    public boolean isValidChecksum() {
      return checksum == calculateChecksum(buffer, headerLength, 0);
    }

    @Override
    public TransportLayer payloadType() {
      return protocol;
    }

    @Override
    public int length() {
      return IPV4_HEADER_LENGTH + ((options == null) ? 0 : options.length);
    }

    @Override
    public Memory buffer() {
      if (buffer == null) {
        buffer = ALLOCATOR.allocate(length());
        buffer.writeByte(((super.version & 0xF) << 4 | headerLength & 0xF));
        buffer.writeByte((((diffServ << 2) & 0x3F) | expCon & 0x3));
        buffer.writeShort(totalLength);
        buffer.writeShort(identification);
        buffer.writeShort((flags & 0x7) << 13 | fragmentOffset & 0x1FFF);
        buffer.writeByte(ttl);
        buffer.writeByte(protocol.value());
        buffer.writeShort(checksum & 0xFFFF);
        buffer.writeBytes(sourceAddress.address());
        buffer.writeBytes(destinationAddress.address());
        if (options != null && options.length > 0 && headerLength > 5) {
          buffer.writeBytes(options);
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
      return headerLength == header.headerLength
          && diffServ == header.diffServ
          && expCon == header.expCon
          && totalLength == header.totalLength
          && identification == header.identification
          && flags == header.flags
          && fragmentOffset == header.fragmentOffset
          && ttl == header.ttl
          && checksum == header.checksum
          && protocol.equals(header.protocol)
          && sourceAddress.equals(header.sourceAddress)
          && destinationAddress.equals(header.destinationAddress)
          && Arrays.equals(options, header.options);
    }

    @Override
    public int hashCode() {
      int result =
          Objects.hash(
              headerLength,
              diffServ,
              expCon,
              totalLength,
              identification,
              flags,
              fragmentOffset,
              ttl,
              protocol,
              checksum,
              sourceAddress,
              destinationAddress);
      result = 31 * result + Arrays.hashCode(options);
      return result;
    }

    @Override
    public String toString() {
      return Strings.toStringBuilder(this)
          .add("version", version())
          .add("headerLength", headerLength() & 0xF)
          .add("diffServ", diffServ() & 0x3F)
          .add("expCon", expCon() & 0x3)
          .add("totalLength", totalLength() & 0xFFFF)
          .add("identification", identification() & 0xFFFF)
          .add("flags", flags() & 0x7)
          .add("fragmentOffset", fragmentOffset() & 0x1FFF)
          .add("ttl", ttl() & 0xFFFF)
          .add("protocol", protocol())
          .add("checksum", checksum() & 0xFFFF)
          .add("sourceAddress", sourceAddress())
          .add("destinationAddress", destinationAddress())
          .add("options", Arrays.toString(options()))
          .add("validChecksum", isValidChecksum())
          .toString();
    }
  }

  public static final class Builder extends AbstractPaketBuilder {

    private byte headerLength;
    private byte diffServ;
    private byte expCon;
    private short totalLength;
    private short identification;
    private byte flags;
    private short fragmentOffset;
    private byte ttl;
    private TransportLayer protocol = TransportLayer.TCP;
    private short checksum;
    private Inet4Address sourceAddress = Inet4Address.ZERO;
    private Inet4Address destinationAddress = Inet4Address.ZERO;
    private byte[] options = new byte[0];

    private Memory buffer;
    private Memory payloadBuffer;

    /** A helper field. */
    private boolean calculateChecksum;

    public Builder headerLength(final int headerLength) {
      this.headerLength = (byte) (headerLength & 0xF);
      return this;
    }

    public Builder diffServ(final int diffServ) {
      this.diffServ = (byte) (diffServ & 0x3F);
      return this;
    }

    public Builder expCon(final int expCon) {
      this.expCon = (byte) (expCon & 0x3);
      return this;
    }

    public Builder totalLength(final int totalLength) {
      this.totalLength = (short) (totalLength & 0xFFFF);
      return this;
    }

    public Builder identification(final int identification) {
      this.identification = (short) (identification & 0xFFFF);
      return this;
    }

    public Builder flags(final int flags) {
      this.flags = (byte) (flags & 0x7);
      return this;
    }

    public Builder fragmentOffset(final int fragmentOffset) {
      this.fragmentOffset = (short) (fragmentOffset & 0x1FFF);
      return this;
    }

    public Builder ttl(final int ttl) {
      this.ttl = (byte) (ttl & 0xFF);
      return this;
    }

    public Builder protocol(TransportLayer protocol) {
      this.protocol = protocol;
      return this;
    }

    public Builder checksum(final int checksum) {
      this.checksum = (short) (checksum & 0xFFFF);
      return this;
    }

    public Builder sourceAddress(final Inet4Address sourceAddress) {
      this.sourceAddress = sourceAddress;
      return this;
    }

    public Builder destinationAddress(final Inet4Address destinationAddress) {
      this.destinationAddress = destinationAddress;
      return this;
    }

    public Builder calculateChecksum(boolean calculateChecksum) {
      this.calculateChecksum = calculateChecksum;
      return this;
    }

    /**
     * Add options.
     *
     * @param options options.
     * @return returns this {@link Builder} object.
     */
    public Builder options(final byte[] options) {
      this.options = new byte[options.length];
      System.arraycopy(options, 0, this.options, 0, this.options.length);
      return this;
    }

    @Override
    public Ip4 build() {
      if (calculateChecksum) {
        if (buffer == null) {
          buffer = new Ip4(this).buffer();
        }
        checksum(Ip4.Header.calculateChecksum(buffer, headerLength, 0));
        buffer.setShort(10, this.checksum);
      }
      return new Ip4(this);
    }

    @Override
    public Ip4 build(final Memory buffer) {
      resetIndex(buffer);
      this.headerLength = (byte) (buffer.readByte() & 0xF);
      byte tmp = buffer.readByte();
      this.diffServ = (byte) ((tmp >> 2) & 0x3F);
      this.expCon = (byte) (tmp & 0x3);
      this.totalLength = buffer.readShort();
      this.identification = buffer.readShort();
      short sscratch = buffer.readShort();
      this.flags = (byte) (sscratch >> 13 & 0x7);
      this.fragmentOffset = (short) (sscratch & 0x1FFF);
      this.ttl = buffer.readByte();
      this.protocol = TransportLayer.valueOf(buffer.readByte());
      this.checksum = (short) (buffer.readShort() & 0xFFFF);
      byte[] ipv4Buffer;
      ipv4Buffer = new byte[Inet4Address.IPV4_ADDRESS_LENGTH];
      buffer.readBytes(ipv4Buffer);
      this.sourceAddress = Inet4Address.valueOf(ipv4Buffer);
      ipv4Buffer = new byte[Inet4Address.IPV4_ADDRESS_LENGTH];
      buffer.readBytes(ipv4Buffer);
      this.destinationAddress = Inet4Address.valueOf(ipv4Buffer);
      if (headerLength > 5) {
        int optionsLength = (headerLength - 5) * 4;
        this.options = new byte[optionsLength];
        buffer.readBytes(options);
      } else {
        options = new byte[0];
      }
      this.buffer = buffer;
      this.payloadBuffer = buffer.slice();
      return new Ip4(this);
    }

    @Override
    public Builder reset() {
      return reset(readerIndex, Header.IPV4_HEADER_LENGTH);
    }

    @Override
    public Builder reset(int offset, int length) {
      if (buffer != null) {
        Validate.notIllegalArgument(offset + length <= buffer.capacity());
        Validate.notIllegalArgument((headerLength & 0xF) >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument((diffServ & 0x3F) >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument((expCon & 0x3) >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument((totalLength & 0xFFFF) >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument((identification & 0xFFFF) >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument((flags & 0x7) >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument((fragmentOffset & 0x1FFF) >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument((ttl & 0xFF) >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(protocol != null, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(checksum >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(sourceAddress != null, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(destinationAddress != null, ILLEGAL_HEADER_EXCEPTION);
        int index = offset;
        buffer.setByte(index, (((0x4 & 0xF) << 4) | this.headerLength & 0xF));
        index += 1;
        int tmp = ((diffServ << 2) & 0x3F) | (expCon & 0x3);
        buffer.setByte(index, tmp);
        index += 1;
        buffer.setShort(index, totalLength);
        index += 2;
        buffer.setShort(index, identification);
        index += 2;
        buffer.setShort(index, (flags & 0x7) << 13 | fragmentOffset & 0x1FFF);
        index += 2;
        buffer.setByte(index, ttl);
        index += 1;
        buffer.setByte(index, protocol.value());
        index += 1;
        buffer.setShort(index, checksum);
        index += 2;
        buffer.setBytes(index, sourceAddress.address());
        index += Inet4Address.IPV4_ADDRESS_LENGTH;
        buffer.setBytes(index, destinationAddress.address());
        index += Inet4Address.IPV4_ADDRESS_LENGTH;
        buffer.setBytes(index, options);
      }
      return this;
    }
  }
}
