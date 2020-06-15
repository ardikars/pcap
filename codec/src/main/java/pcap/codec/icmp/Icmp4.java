/** This code is licenced under the GPL version 2. */
package pcap.codec.icmp;

import pcap.codec.AbstractPacket;
import pcap.codec.Packet;
import pcap.codec.icmp.icmp4.*;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;
import pcap.common.util.NamedNumber;
import pcap.common.util.Strings;
import pcap.common.util.Validate;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class Icmp4 extends AbstractPacket {

  static {
    try {
      Class.forName(Icmp4DestinationUnreachable.class.getName());
      Class.forName(Icmp4EchoReply.class.getName());
      Class.forName(Icmp4EchoRequest.class.getName());
      Class.forName(Icmp4ParameterProblem.class.getName());
      Class.forName(Icmp4RedirectMessage.class.getName());
      Class.forName(Icmp4RouterAdvertisement.class.getName());
      Class.forName(Icmp4RouterSolicitation.class.getName());
      Class.forName(Icmp4TimeExceeded.class.getName());
      Class.forName(Icmp4Timestamp.class.getName());
      Class.forName(Icmp4TimestampReply.class.getName());
    } catch (ClassNotFoundException e) {
      //
    }
  }

  private final Header header;
  private final Packet payload;
  private final Builder builder;

  private Icmp4(Builder builder) {
    this.header = new Header(builder);
    this.payloadBuffer = builder.payloadBuffer;
    if (this.payloadBuffer != null
        && this.payloadBuffer.readerIndex() < this.payloadBuffer.writerIndex()) {
      this.payload =
          Icmp.IcmpTypeAndCode.valueOf(this.header.payloadType().value().byteValue())
              .newInstance(this.payloadBuffer);
    } else {
      this.payload = null;
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
        .add("payload", payload != null ? payload.getClass().getSimpleName() : "(None)")
        .toString();
  }

  public static class Header extends Icmp.AbstractPacketHeader {

    private final Builder builder;

    private Header(Builder builder) {
      typeAndCode = builder.typeAndCode;
      checksum = builder.checksum;
      buffer = resetIndex(builder.buffer, length());
      this.builder = builder;
    }

    @SuppressWarnings("TypeParameterUnusedInFormals")
    @Override
    public <T extends NamedNumber> T payloadType() {
      return (T) typeAndCode;
    }

    @Override
    public Builder builder() {
      return builder;
    }

    @Override
    public String toString() {
      return Strings.toStringBuilder(this)
          .add("typeAndCode", typeAndCode)
          .add("checksum", checksum)
          .toString();
    }
  }

  public static class Builder extends Icmp.AbstractPacketBuilder {

    private Memory buffer;
    private Memory payloadBuffer;

    private boolean calculateChecksum;

    private Builder calculateChecksum(boolean caculateChecksum) {
      this.calculateChecksum = caculateChecksum;
      return this;
    }

    @Override
    public Packet build() {
      return new Icmp4(this);
    }

    @Override
    public Packet build(Memory buffer) {
      resetIndex(buffer);
      byte type = buffer.readByte();
      byte code = buffer.readByte();
      super.typeAndCode = Icmp.findIcmpTypeAndCode(type, code, Icmp.IcmpTypeAndCode.ICMP4_REGISTRY);
      super.checksum = buffer.readShort();
      if (calculateChecksum) {
        int index = 0;
        int accumulation = 0;
        for (int i = 0; i < buffer.capacity() / 2; ++i) {
          accumulation += 0xffff & buffer.getShort(index);
          index += 2;
        }
        // pad to an even number of shorts
        if (buffer.capacity() % 2 > 0) {
          accumulation += (buffer.getByte(index) & 0xff) << 8;
          index++;
        }
        accumulation = (accumulation >> 16 & 0xffff) + (accumulation & 0xffff);
        short checksum = (short) (~accumulation & 0xffff);
        super.checksum = buffer.readShort();
        if (checksum != super.checksum) {
          // invalid checksum
          this.checksum = 0;
        }
      }
      this.buffer = buffer;
      this.payloadBuffer = buffer.slice();
      return new Icmp4(this);
    }

    @Override
    public Builder reset() {
      return reset(readerIndex, Header.ICMP_HEADER_LENGTH);
    }

    @Override
    public Builder reset(int offset, int length) {
      if (buffer != null) {
        Validate.notIllegalArgument(offset + length <= buffer.capacity());
        Validate.notIllegalArgument(typeAndCode != null, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(checksum >= 0, ILLEGAL_HEADER_EXCEPTION);
        int index = offset;
        buffer.setByte(index, typeAndCode.type());
        index += 1;
        buffer.setByte(index, typeAndCode.code());
        index += 1;
        buffer.setShort(index, checksum);
      }
      return this;
    }
  }
}
