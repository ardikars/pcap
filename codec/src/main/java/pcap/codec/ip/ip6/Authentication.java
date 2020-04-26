/** This code is licenced under the GPL version 2. */
package pcap.codec.ip.ip6;

import pcap.codec.AbstractPacket;
import pcap.codec.Packet;
import pcap.codec.TransportLayer;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;
import pcap.common.util.Strings;
import pcap.common.util.Validate;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class Authentication extends AbstractPacket {

  private final Header header;
  private final Packet payload;
  private final Builder builder;

  private Authentication(final Builder builder) {
    this.header = new Header(builder);
    this.payloadBuffer = builder.payloadBuffer;
    if (this.payloadBuffer != null) {
      this.payload =
          TransportLayer.valueOf(header.payloadType().value()).newInstance(this.payloadBuffer);
    } else {
      payload = null;
    }
    this.builder = builder;
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
        .add("payload", payload == null ? payload.getClass().getSimpleName() : "(None)")
        .toString();
  }

  public static final class Header extends AbstractPacket.Header {

    public static final byte FIXED_HEADER_LENGTH = 12; // bytes

    private final TransportLayer nextHeader;
    private final byte payloadLength;
    private final int securityParameterIndex;
    private final int sequenceNumber;
    private final byte[] integrityCheckValue;

    private final Builder builder;

    private Header(final Builder builder) {
      this.nextHeader = builder.nextHeader;
      this.payloadLength = builder.payloadLength;
      this.securityParameterIndex = builder.securityParameterIndex;
      this.sequenceNumber = builder.sequenceNumber;
      this.integrityCheckValue = builder.integrityCheckValue;
      this.buffer = slice(builder.buffer, length());
      this.builder = builder;
    }

    public TransportLayer nextHeader() {
      return nextHeader;
    }

    public int payloadLength() {
      return payloadLength & 0xff;
    }

    public int securityParameterIndex() {
      return securityParameterIndex;
    }

    public int sequenceNumber() {
      return sequenceNumber;
    }

    /**
     * Get integrity check value.
     *
     * @return returns check integrity check value.
     */
    public byte[] integrityCheckValue() {
      byte[] integrityCheckValue = new byte[this.integrityCheckValue.length];
      System.arraycopy(
          this.integrityCheckValue, 0, integrityCheckValue, 0, this.integrityCheckValue.length);
      return integrityCheckValue;
    }

    @Override
    public TransportLayer payloadType() {
      return nextHeader;
    }

    @Override
    public int length() {
      return FIXED_HEADER_LENGTH + ((integrityCheckValue == null) ? 0 : integrityCheckValue.length);
    }

    @Override
    public Memory buffer() {
      if (buffer == null) {
        buffer = ALLOCATOR.allocate(length());
        buffer.writeByte(nextHeader.value());
        buffer.writeByte(payloadLength);
        buffer.writeShort((short) 0); // reserved
        buffer.writeInt(sequenceNumber);
        buffer.writeInt(securityParameterIndex);
        if (integrityCheckValue != null) {
          buffer.writeBytes(integrityCheckValue);
        }
      }
      return buffer;
    }

    @Override
    public Builder builder() {
      return builder;
    }

    @Override
    public String toString() {
      return Strings.toStringBuilder(this)
          .add("nextHeader", nextHeader)
          .add("payloadLength", payloadLength)
          .add("securityParameterIndex", securityParameterIndex)
          .add("sequenceNumber", sequenceNumber)
          .add("integrityCheckValue", Strings.hex(integrityCheckValue))
          .toString();
    }
  }

  public static final class Builder extends AbstractPacket.Builder {

    private TransportLayer nextHeader;
    private byte payloadLength;
    private int securityParameterIndex;
    private int sequenceNumber;
    private byte[] integrityCheckValue;

    private Memory buffer;
    private Memory payloadBuffer;

    public Builder nextHeader(final TransportLayer nextHeader) {
      this.nextHeader = nextHeader;
      return this;
    }

    public Builder payloadLength(final int payloadLength) {
      this.payloadLength = (byte) (payloadLength & 0xff);
      return this;
    }

    public Builder securityParameterIndex(final int securityParameterIndex) {
      this.securityParameterIndex = securityParameterIndex;
      return this;
    }

    public Builder sequenceNumber(final int sequenceNumber) {
      this.sequenceNumber = sequenceNumber;
      return this;
    }

    /**
     * Add integrity check value.
     *
     * @param integrityCheckValue integrity check value.
     * @return returns this {@link Builder} object.
     */
    public Builder integrityCheckValue(final byte[] integrityCheckValue) {
      this.integrityCheckValue = new byte[integrityCheckValue.length];
      System.arraycopy(
          integrityCheckValue, 0, this.integrityCheckValue, 0, this.integrityCheckValue.length);
      return this;
    }

    @Override
    public Packet build() {
      return new Authentication(this);
    }

    @Override
    public Packet build(final Memory buffer) {
      resetIndex(buffer);
      this.nextHeader = TransportLayer.valueOf(buffer.readByte());
      this.payloadLength = buffer.readByte();
      buffer.skipBytes(2); // reserved
      this.securityParameterIndex = buffer.readInt();
      this.sequenceNumber = buffer.readInt();
      this.integrityCheckValue = new byte[(this.payloadLength + 2) * 4 - 12];
      if (this.integrityCheckValue != null) {
        buffer.readBytes(this.integrityCheckValue);
      }
      this.buffer = buffer;
      this.payloadBuffer = buffer.slice();
      return new Authentication(this);
    }

    @Override
    public Builder reset() {
      return reset(readerIndex, Header.FIXED_HEADER_LENGTH);
    }

    @Override
    public Builder reset(int offset, int length) {
      if (buffer != null) {
        Validate.notIllegalArgument(offset + length <= buffer.capacity());
        Validate.notIllegalArgument(nextHeader != null, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(payloadLength >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(securityParameterIndex >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(sequenceNumber >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(integrityCheckValue != null, ILLEGAL_HEADER_EXCEPTION);
        int index = offset;
        buffer.setByte(index, nextHeader.value());
        index += 1;
        buffer.setByte(index, payloadLength);
        index += 1;
        buffer.setInt(index, securityParameterIndex);
        index += 4;
        buffer.setInt(index, sequenceNumber);
        index += 4;
        buffer.setBytes(index, integrityCheckValue);
      }
      return this;
    }
  }
}
