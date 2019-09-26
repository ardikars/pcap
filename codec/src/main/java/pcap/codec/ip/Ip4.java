/** This code is licenced under the GPL version 2. */
package pcap.codec.ip;

import java.util.Arrays;
import pcap.codec.Packet;
import pcap.codec.TransportLayer;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;
import pcap.common.net.Inet4Address;
import pcap.common.util.Validate;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class Ip4 extends Ip {

  private final Header header;
  private final Packet payload;

  private Ip4(final Builder builder) {
    this.header = new Header(builder);
    this.payload =
        TransportLayer.valueOf(this.header.getPayloadType().getValue())
            .newInstance(builder.payloadBuffer);
    payloadBuffer = builder.payloadBuffer;
  }

  @Override
  public Header getHeader() {
    return header;
  }

  @Override
  public Packet getPayload() {
    return payload;
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
      this.buffer = slice(builder.buffer, getLength());
      this.builder = builder;
    }

    public int getHeaderLength() {
      return headerLength & 0xf;
    }

    public int getDiffServ() {
      return diffServ & 0x3f;
    }

    public int getExpCon() {
      return expCon & 0x3;
    }

    public int getTotalLength() {
      return totalLength & 0xffff;
    }

    public int getIdentification() {
      return identification & 0xffff;
    }

    public int getFlags() {
      return flags & 0x7;
    }

    public int getFragmentOffset() {
      return fragmentOffset & 0x1fff;
    }

    public int getTtl() {
      return ttl & 0xff;
    }

    public TransportLayer getProtocol() {
      return protocol;
    }

    public int getChecksum() {
      return checksum & 0xffff;
    }

    public Inet4Address getSourceAddress() {
      return sourceAddress;
    }

    public Inet4Address getDestinationAddress() {
      return destinationAddress;
    }

    /**
     * Get options.
     *
     * @return returns options.
     */
    public byte[] getOptions() {
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
      int accumulation = 0;
      for (int i = 0; i < headerLength * 2; ++i) {
        accumulation += 0xffff & buffer.getShort(i + 2);
      }
      accumulation = (accumulation >> 16 & 0xffff) + (accumulation & 0xffff);
      return checksum == (short) (~accumulation & 0xffff);
    }

    @Override
    public TransportLayer getPayloadType() {
      return protocol;
    }

    @Override
    public int getLength() {
      return IPV4_HEADER_LENGTH + ((options == null) ? 0 : options.length);
    }

    @Override
    public Memory getBuffer() {
      if (buffer == null) {
        buffer = ALLOCATOR.allocate(getLength());
        buffer.writeByte((byte) ((super.version & 0xf) << 4 | headerLength & 0xf));
        buffer.writeByte((byte) (((diffServ << 2) & 0x3f) | expCon & 0x3));
        buffer.writeShort(totalLength);
        buffer.writeShort(identification);
        buffer.writeShort((flags & 0x7) << 13 | fragmentOffset & 0x1fff);
        buffer.writeByte(ttl);
        buffer.writeByte(protocol.getValue());
        buffer.writeShort(checksum & 0xffff);
        buffer.writeBytes(sourceAddress.toBytes());
        buffer.writeBytes(destinationAddress.toBytes());
        if (options != null && headerLength > 5) {
          buffer.writeBytes(options);
        }
      }
      return buffer;
    }

    @Override
    public Builder getBuilder() {
      return builder;
    }

    @Override
    public String toString() {
      return new StringBuilder()
          .append("\tversion: ")
          .append(version)
          .append('\n')
          .append("\theaderLength: ")
          .append(headerLength)
          .append('\n')
          .append("\tdiffServ: ")
          .append(diffServ)
          .append('\n')
          .append("\texpCon: ")
          .append(expCon)
          .append('\n')
          .append("\ttotalLength: ")
          .append(totalLength)
          .append('\n')
          .append("\tidentification: ")
          .append(identification)
          .append('\n')
          .append("\tflags: ")
          .append(flags)
          .append('\n')
          .append("\tfragmentOffset: ")
          .append(fragmentOffset)
          .append('\n')
          .append("\tttl: ")
          .append(ttl)
          .append('\n')
          .append("\tprotocol: ")
          .append(protocol)
          .append('\n')
          .append("\tchecksum: ")
          .append(checksum)
          .append('\n')
          .append("\tsourceAddress: ")
          .append(sourceAddress)
          .append('\n')
          .append("\tdestinationAddress: ")
          .append(destinationAddress)
          .append('\n')
          .append("\toptions: ")
          .append(Arrays.toString(options))
          .append('\n')
          .toString();
    }
  }

  @Override
  public String toString() {
    return new StringBuilder("[ Ip4 Header (")
        .append(getHeader().getLength())
        .append(" bytes) ]")
        .append('\n')
        .append(header)
        .append("\tpayload: ")
        .append(payload != null ? payload.getClass().getSimpleName() : "")
        .toString();
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
    private TransportLayer protocol;
    private short checksum;
    private Inet4Address sourceAddress;
    private Inet4Address destinationAddress;
    private byte[] options;

    private Memory buffer;
    private Memory payloadBuffer;

    /** A helper field. */
    private boolean calculateChecksum;

    public Builder headerLength(final int headerLength) {
      this.headerLength = (byte) (headerLength & 0xf);
      return this;
    }

    public Builder diffServ(final int diffServ) {
      this.diffServ = (byte) (this.diffServ & 0x3f);
      return this;
    }

    public Builder expCon(final int expCon) {
      this.expCon = (byte) (expCon & 0x3);
      return this;
    }

    public Builder totalLength(final int totalLength) {
      this.totalLength = (short) (totalLength & 0xffff);
      return this;
    }

    public Builder identification(final int identification) {
      this.identification = (short) (identification & 0xffff);
      return this;
    }

    public Builder flags(final int flags) {
      this.flags = (byte) (flags & 0x7);
      return this;
    }

    public Builder fragmentOffset(final int fragmentOffset) {
      this.fragmentOffset = (short) (fragmentOffset & 0x1fff);
      return this;
    }

    public Builder ttl(final int ttl) {
      this.ttl = (byte) (ttl & 0xff);
      return this;
    }

    public Builder protocol(TransportLayer protocol) {
      this.protocol = protocol;
      return this;
    }

    public Builder checksum(final int checksum) {
      this.checksum = (short) (this.checksum & 0xffff);
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
    public Packet build() {
      return new Ip4(this);
    }

    @Override
    public Packet build(final Memory buffer) {
      this.headerLength = (byte) (buffer.readByte() & 0xf);
      byte tmp = buffer.readByte();
      this.diffServ = (byte) ((tmp >> 2) & 0x3f);
      this.expCon = (byte) (tmp & 0x3);
      this.totalLength = buffer.readShort();
      this.identification = buffer.readShort();
      short sscratch = buffer.readShort();
      this.flags = (byte) (sscratch >> 13 & 0x7);
      this.fragmentOffset = (short) (sscratch & 0x1fff);
      this.ttl = buffer.readByte();
      this.protocol = TransportLayer.valueOf(buffer.readByte());
      this.checksum = (short) (buffer.readShort() & 0xffff);
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
      if (calculateChecksum) {
        int index = 0;
        int accumulation = 0;
        for (int i = 0; i < headerLength * 2; ++i) {
          accumulation += 0xffff & buffer.getShort(index);
          index += 2;
        }
        accumulation = (accumulation >> 16 & 0xffff) + (accumulation & 0xffff);
        if (checksum != (short) (~accumulation & 0xffff)) {
          this.checksum = 0;
        }
      }
      this.buffer = buffer;
      this.payloadBuffer = buffer.slice();
      return new Ip4(this);
    }

    @Override
    public void reset() {
      if (buffer != null) {
        reset(0, Header.IPV4_HEADER_LENGTH);
      }
    }

    @Override
    public void reset(int offset, int length) {
      if (buffer != null) {
        Validate.notIllegalArgument(offset + length <= buffer.capacity());
        Validate.notIllegalArgument(headerLength >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(diffServ >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(expCon >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(totalLength >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(identification >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(flags >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(fragmentOffset >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(ttl >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(protocol != null, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(checksum >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(sourceAddress != null, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(destinationAddress != null, ILLEGAL_HEADER_EXCEPTION);
        int index = offset;
        buffer.setByte(index, ((4 & 0xf) << 4) | this.headerLength & 0xf);
        index += 1;
        int tmp = ((diffServ << 2) & 0x3f) | (expCon & 0x3);
        buffer.setByte(index, tmp);
        index += 1;
        buffer.setShort(index, totalLength);
        index += 2;
        buffer.setShort(index, identification);
        index += 2;
        int sscratch = ((flags << 13) & 0x7) | (fragmentOffset & 0x1fff);
        buffer.setShort(index, sscratch);
        index += 2;
        buffer.setByte(index, ttl);
        index += 1;
        buffer.setByte(index, protocol.getValue());
        index += 1;
        buffer.setShort(index, checksum);
        index += 2;
        buffer.setBytes(index, sourceAddress.toBytes());
        index += Inet4Address.IPV4_ADDRESS_LENGTH;
        buffer.setBytes(index, destinationAddress.toBytes());
        index += Inet4Address.IPV4_ADDRESS_LENGTH;
        buffer.setBytes(index, options);
      }
    }
  }
}
