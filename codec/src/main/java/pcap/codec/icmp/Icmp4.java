/** This code is licenced under the GPL version 2. */
package pcap.codec.icmp;

import java.util.Collection;
import java.util.HashSet;
import pcap.codec.AbstractPacket;
import pcap.codec.Packet;
import pcap.codec.icmp.icmp4.Icmp4DestinationUnreachable;
import pcap.codec.icmp.icmp4.Icmp4EchoReply;
import pcap.codec.icmp.icmp4.Icmp4EchoRequest;
import pcap.codec.icmp.icmp4.Icmp4ParameterProblem;
import pcap.codec.icmp.icmp4.Icmp4RedirectMessage;
import pcap.codec.icmp.icmp4.Icmp4RouterAdvertisement;
import pcap.codec.icmp.icmp4.Icmp4RouterSolicitation;
import pcap.codec.icmp.icmp4.Icmp4TimeExceeded;
import pcap.codec.icmp.icmp4.Icmp4Timestamp;
import pcap.codec.icmp.icmp4.Icmp4TimestampReply;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;
import pcap.common.util.NamedNumber;
import pcap.common.util.Validate;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class Icmp4 extends AbstractPacket {

  public static final Collection<Icmp.IcmpTypeAndCode> ICMP4_REGISTRY =
      new HashSet<Icmp.IcmpTypeAndCode>();

  private final Header header;
  private final Packet payload;

  private Icmp4(Builder builder) {
    this.header = new Header(builder);
    this.payload =
        Icmp.IcmpTypeAndCode.valueOf(this.header.getPayloadType().getValue().byteValue())
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

  public static class Header extends Icmp.AbstractPacketHeader {

    private final Builder builder;

    private Header(Builder builder) {
      typeAndCode = builder.typeAndCode;
      checksum = builder.checksum;
      buffer = slice(builder.buffer, getLength());
      this.builder = builder;
    }

    @SuppressWarnings("TypeParameterUnusedInFormals")
    @Override
    public <T extends NamedNumber> T getPayloadType() {
      return (T) typeAndCode;
    }

    @Override
    public Builder getBuilder() {
      return builder;
    }

    @Override
    public String toString() {
      return new StringBuilder()
          .append("\ttypeAndCode: ")
          .append(typeAndCode)
          .append('\n')
          .append("\tchecksum: ")
          .append(checksum)
          .append('\n')
          .toString();
    }
  }

  @Override
  public String toString() {
    return new StringBuilder("[ Icmp4 Header (")
        .append(getHeader().getLength())
        .append(" bytes) ]")
        .append('\n')
        .append(header)
        .append("\tpayload: ")
        .append(payload != null ? payload.getClass().getSimpleName() : "")
        .toString();
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
      byte type = buffer.readByte();
      byte code = buffer.readByte();
      super.typeAndCode = Icmp.findIcmpTypeAndCode(type, code, Icmp4.ICMP4_REGISTRY);
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
    public void reset() {
      if (buffer != null) {
        reset(0, Header.ICMP_HEADER_LENGTH);
      }
    }

    @Override
    public void reset(int offset, int length) {
      if (buffer != null) {
        Validate.notIllegalArgument(offset + length <= buffer.capacity());
        Validate.notIllegalArgument(typeAndCode != null, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(checksum >= 0, ILLEGAL_HEADER_EXCEPTION);
        int index = offset;
        buffer.setByte(index, typeAndCode.getType());
        index += 1;
        buffer.setByte(index, typeAndCode.getCode());
        index += 1;
        buffer.setShort(index, checksum);
      }
    }
  }

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
}
