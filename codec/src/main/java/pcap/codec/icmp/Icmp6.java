/** This code is licenced under the GPL version 2. */
package pcap.codec.icmp;

import java.util.Collection;
import java.util.HashSet;
import pcap.codec.AbstractPacket;
import pcap.codec.Packet;
import pcap.codec.icmp.icmp6.*;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;
import pcap.common.util.NamedNumber;
import pcap.common.util.Validate;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class Icmp6 extends AbstractPacket {

  public static final Collection<Icmp.IcmpTypeAndCode> ICMP6_REGISTRY =
      new HashSet<Icmp.IcmpTypeAndCode>();

  private final Header header;
  private final Packet payload;

  /**
   * Build icmpv6 packet.
   *
   * @param builder builder.
   */
  public Icmp6(Builder builder) {
    this.header = new Header(builder);
    this.payloadBuffer = builder.payloadBuffer;
    if (this.payloadBuffer != null) {
      this.payload =
          Icmp.IcmpTypeAndCode.valueOf(this.header.payloadType().value().byteValue())
              .newInstance(this.payloadBuffer);
    } else {
      this.payload = null;
    }
  }

  @Override
  public Header header() {
    return header;
  }

  @Override
  public Packet payload() {
    return payload;
  }

  public static class Header extends Icmp.AbstractPacketHeader {

    private final Builder builder;

    private Header(Builder builder) {
      typeAndCode = builder.typeAndCode;
      checksum = builder.checksum;
      buffer = slice(builder.buffer, length());
      this.builder = builder;
    }

    @SuppressWarnings("TypeParameterUnusedInFormals")
    @Override
    public <T extends NamedNumber> T payloadType() {
      return (T) typeAndCode;
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

    @Override
    public AbstractPacket.Builder builder() {
      return builder;
    }
  }

  @Override
  public String toString() {
    return new StringBuilder("[ Icmp6 Header (")
        .append(header().length())
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

    @Override
    public Packet build() {
      return new Icmp6(this);
    }

    @Override
    public Packet build(Memory buffer) {
      byte type = buffer.readByte();
      byte code = buffer.readByte();
      super.typeAndCode = Icmp.findIcmpTypeAndCode(type, code, Icmp6.ICMP6_REGISTRY);
      super.checksum = buffer.readShort();
      this.buffer = buffer;
      this.payloadBuffer = buffer.slice();
      return new Icmp6(this);
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
        buffer.setByte(index, typeAndCode.type());
        index += 1;
        buffer.setByte(index, typeAndCode.code());
        index += 1;
        buffer.setShort(index, checksum);
      }
    }
  }

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
}
