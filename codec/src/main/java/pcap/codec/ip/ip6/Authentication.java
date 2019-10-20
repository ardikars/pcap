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

  private Authentication(final Builder builder) {
    this.header = new Header(builder);
    this.payloadBuffer = builder.payloadBuffer;
    if (this.payloadBuffer != null) {
      this.payload =
          TransportLayer.valueOf(header.getPayloadType().getValue())
              .newInstance(this.payloadBuffer);
    } else {
      payload = null;
    }
  }

  @Override
  public Packet.Header getHeader() {
    return header;
  }

  @Override
  public Packet getPayload() {
    return payload;
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
      this.buffer = slice(builder.buffer, getLength());
      this.builder = builder;
    }

    public TransportLayer getNextHeader() {
      return nextHeader;
    }

    public int getPayloadLength() {
      return payloadLength & 0xff;
    }

    public int getSecurityParameterIndex() {
      return securityParameterIndex;
    }

    public int getSequenceNumber() {
      return sequenceNumber;
    }

    /**
     * Get integrity check value.
     *
     * @return returns check integrity check value.
     */
    public byte[] getIntegrityCheckValue() {
      byte[] integrityCheckValue = new byte[this.integrityCheckValue.length];
      System.arraycopy(
          this.integrityCheckValue, 0, integrityCheckValue, 0, this.integrityCheckValue.length);
      return integrityCheckValue;
    }

    @Override
    public TransportLayer getPayloadType() {
      return nextHeader;
    }

    @Override
    public int getLength() {
      return FIXED_HEADER_LENGTH + ((integrityCheckValue == null) ? 0 : integrityCheckValue.length);
    }

    @Override
    public Memory getBuffer() {
      if (buffer == null) {
        buffer = ALLOCATOR.allocate(getLength());
        buffer.setByte(0, nextHeader.getValue());
        buffer.setByte(1, payloadLength);
        buffer.setShort(2, (short) 0); // reserved
        buffer.setInt(4, sequenceNumber);
        buffer.setInt(8, securityParameterIndex);
        if (integrityCheckValue != null) {
          buffer.setBytes(12, integrityCheckValue);
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
          .append("\t\tnextHeader: ")
          .append(nextHeader)
          .append('\n')
          .append("\t\tpayloadLength: ")
          .append(payloadLength)
          .append('\n')
          .append("\t\tsecurityParameterIndex: ")
          .append(securityParameterIndex)
          .append('\n')
          .append("\t\tsequenceNumber: ")
          .append(sequenceNumber)
          .append('\n')
          .append("\t\tintegrityCheckValue: ")
          .append(Strings.toHexString(integrityCheckValue))
          .append('\n')
          .toString();
    }
  }

  @Override
  public String toString() {
    return new StringBuilder("\t[ Authentication Header (")
        .append(getHeader().getLength())
        .append(" bytes) ]")
        .append('\n')
        .append(header)
        .append("\t\tpayload: ")
        .append(payload != null ? payload.getClass().getSimpleName() : "")
        .toString();
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
    public void reset() {
      if (buffer != null) {
        reset(0, Header.FIXED_HEADER_LENGTH);
      }
    }

    @Override
    public void reset(int offset, int length) {
      if (buffer != null) {
        Validate.notIllegalArgument(offset + length <= buffer.capacity());
        Validate.notIllegalArgument(nextHeader != null, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(payloadLength >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(securityParameterIndex >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(sequenceNumber >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(integrityCheckValue != null, ILLEGAL_HEADER_EXCEPTION);
        int index = offset;
        buffer.setByte(index, nextHeader.getValue());
        index += 1;
        buffer.setByte(index, payloadLength);
        index += 1;
        buffer.setInt(index, securityParameterIndex);
        index += 4;
        buffer.setInt(index, sequenceNumber);
        index += 4;
        buffer.setBytes(index, integrityCheckValue);
      }
    }
  }
}
