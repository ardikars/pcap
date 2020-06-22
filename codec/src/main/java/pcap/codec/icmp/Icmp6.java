/** This code is licenced under the GPL version 2. */
package pcap.codec.icmp;

import pcap.codec.AbstractPacket;
import pcap.codec.Packet;
import pcap.codec.icmp.icmp6.*;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;
import pcap.common.util.NamedNumber;
import pcap.common.util.Strings;
import pcap.common.util.Validate;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class Icmp6 extends AbstractPacket {

  static {
    try {
      Class.forName(Icmp6DestinationUnreachable.class.getName());
      Class.forName(Icmp6EchoReply.class.getName());
      Class.forName(Icmp6EchoRequest.class.getName());
      Class.forName(Icmp6HomeAgentAddressDiscoveryReply.class.getName());
      Class.forName(Icmp6HomeAgentAddressDiscoveryRequest.class.getName());
      Class.forName(Icmp6InverseNeighborDiscoveryAdvertisement.class.getName());
      Class.forName(Icmp6InverseNeighborDiscoverySolicitation.class.getName());
      Class.forName(Icmp6MobilePrefixAdvertisement.class.getName());
      Class.forName(Icmp6MobilePrefixSolicitation.class.getName());
      Class.forName(Icmp6MulticastListenerDone.class.getName());
      Class.forName(Icmp6MulticastListenerQuery.class.getName());
      Class.forName(Icmp6MulticastListenerReportV1.class.getName());
      Class.forName(Icmp6MulticastListenerReportV2.class.getName());
      Class.forName(Icmp6NeighborAdvertisement.class.getName());
      Class.forName(Icmp6NeighborSolicitation.class.getName());
      Class.forName(Icmp6NodeInformationQuery.class.getName());
      Class.forName(Icmp6NodeInformationResponse.class.getName());
      Class.forName(Icmp6PacketTooBigMessage.class.getName());
      Class.forName(Icmp6ParameterProblem.class.getName());
      Class.forName(Icmp6RedirectMessage.class.getName());
      Class.forName(Icmp6RouterAdvertisement.class.getName());
      Class.forName(Icmp6RouterRenumbering.class.getName());
      Class.forName(Icmp6RouterSolicitation.class.getName());
      Class.forName(Icmp6TimeExceeded.class.getName());
    } catch (ClassNotFoundException e) {
      //
    }
  }

  private final Header header;
  private final Packet payload;
  private final Builder builder;

  /**
   * Build icmpv6 packet.
   *
   * @param builder builder.
   */
  public Icmp6(Builder builder) {
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

    /**
     * Type and code.
     *
     * @return returns type and code.
     */
    public Icmp.IcmpTypeAndCode typeAndCode() {
      return typeAndCode;
    }

    /**
     * Checksum.
     *
     * @return returns checksum.
     */
    public int checksum() {
      return checksum;
    }

    @SuppressWarnings("TypeParameterUnusedInFormals")
    @Override
    public <T extends NamedNumber> T payloadType() {
      return (T) typeAndCode;
    }

    @Override
    public String toString() {
      return Strings.toStringBuilder(this)
          .add("typeAndCode", typeAndCode)
          .add("checksum", checksum)
          .toString();
    }

    @Override
    public AbstractPacket.Builder builder() {
      return builder;
    }
  }

  public static class Builder extends Icmp.AbstractPacketBuilder {

    private Memory buffer;
    private Memory payloadBuffer;

    @Override
    public Builder payload(AbstractPacket packet) {
      this.payloadBuffer = packet.buffer();
      return this;
    }

    @Override
    public Packet build() {
      return new Icmp6(this);
    }

    @Override
    public Packet build(Memory buffer) {
      resetIndex(buffer);
      byte type = buffer.readByte();
      byte code = buffer.readByte();
      super.typeAndCode = Icmp.findIcmpTypeAndCode(type, code, Icmp.IcmpTypeAndCode.ICMP6_REGISTRY);
      super.checksum = buffer.readShort();
      this.buffer = buffer;
      this.payloadBuffer = buffer.slice();
      return new Icmp6(this);
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
