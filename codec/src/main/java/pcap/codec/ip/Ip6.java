/** This code is licenced under the GPL version 2. */
package pcap.codec.ip;

import pcap.codec.AbstractPacket;
import pcap.codec.Packet;
import pcap.codec.TransportLayer;
import pcap.codec.ip.ip6.*;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;
import pcap.common.net.Inet6Address;
import pcap.common.util.Validate;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class Ip6 extends Ip {

  private final Header header;
  private final Packet payload;
  private final Builder builder;

  private Ip6(final Builder builder) {
    this.header = new Header(builder);
    this.payloadBuffer = builder.payloadBuffer;
    if (this.payloadBuffer != null) {
      this.payload =
          TransportLayer.valueOf(this.header.payloadType().value()).newInstance(this.payloadBuffer);
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
  public Memory buffer() {
    return header().buffer();
  }

  @Override
  public Builder builder() {
    return builder;
  }

  public static final class Header extends AbstractPacketHeader {

    public static final int IPV6_HEADER_LENGTH = 40;

    private final byte trafficClass;
    private final int flowLabel;
    private final short payloadLength;
    private final TransportLayer nextHeader;
    private final byte hopLimit;
    private final Inet6Address sourceAddress;
    private final Inet6Address destinationAddress;

    private final Builder builder;

    protected Header(final Builder builder) {
      super((byte) 0x06);
      this.trafficClass = builder.trafficClass;
      this.flowLabel = builder.flowLabel;
      this.payloadLength = builder.payloadLength;
      this.nextHeader = builder.nextHeader;
      this.hopLimit = builder.hopLimit;
      this.sourceAddress = builder.sourceAddress;
      this.destinationAddress = builder.destinationAddress;
      this.buffer = slice(builder.buffer, length());
      this.builder = builder;
    }

    public int trafficClass() {
      return trafficClass & 0xff;
    }

    public int flowLabel() {
      return flowLabel & 0xfffff;
    }

    public int payloadLength() {
      return payloadLength & 0xffff;
    }

    public TransportLayer nextHeader() {
      return nextHeader;
    }

    public int hopLimit() {
      return hopLimit & 0xff;
    }

    public Inet6Address sourceAddress() {
      return sourceAddress;
    }

    public Inet6Address destinationAddress() {
      return destinationAddress;
    }

    @Override
    public TransportLayer payloadType() {
      return nextHeader;
    }

    @Override
    public int length() {
      return IPV6_HEADER_LENGTH;
    }

    @Override
    public Memory buffer() {
      if (buffer == null) {
        buffer = ALLOCATOR.allocate(length());
        buffer.writeInt(
            (super.version & 0xf) << 28 | (trafficClass & 0xff) << 20 | flowLabel & 0xfffff);
        buffer.writeShort(payloadLength);
        buffer.writeByte(nextHeader.value());
        buffer.writeByte(hopLimit);
        buffer.writeBytes(sourceAddress.address());
        buffer.writeBytes(destinationAddress.address());
      }
      return buffer;
    }

    @Override
    public Builder builder() {
      return builder;
    }

    @Override
    public String toString() {
      return new StringBuilder()
          .append("\tversion: ")
          .append(version)
          .append('\n')
          .append("\ttrafficClass: ")
          .append(trafficClass)
          .append('\n')
          .append("\tflowLabel: ")
          .append(flowLabel)
          .append('\n')
          .append("\tpayloadLength: ")
          .append(payloadLength)
          .append('\n')
          .append("\tnextHeader: ")
          .append(nextHeader)
          .append('\n')
          .append("\thopLimit: ")
          .append(hopLimit)
          .append('\n')
          .append("\tsourceAddress: ")
          .append(sourceAddress)
          .append('\n')
          .append("\tdestinationAddress: ")
          .append(destinationAddress)
          .append('\n')
          .toString();
    }
  }

  @Override
  public String toString() {
    return new StringBuilder("[ Ip6 Header (")
        .append(header().length())
        .append(" bytes) ]")
        .append('\n')
        .append(header)
        .append("\tpayload: ")
        .append(payload != null ? payload.getClass().getSimpleName() : "")
        .toString();
  }

  public static final class Builder extends AbstractPaketBuilder {

    private byte trafficClass;
    private int flowLabel;
    private short payloadLength;
    private TransportLayer nextHeader = TransportLayer.TCP;
    private byte hopLimit;
    private Inet6Address sourceAddress = Inet6Address.ZERO;
    private Inet6Address destinationAddress = Inet6Address.ZERO;

    private Memory buffer;
    private Memory payloadBuffer;

    public Builder trafficClass(final int trafficClass) {
      this.trafficClass = (byte) (trafficClass & 0xff);
      return this;
    }

    public Builder flowLabel(final int flowLabel) {
      this.flowLabel = flowLabel & 0xfffff;
      return this;
    }

    public Builder payloadLength(final int payloadLength) {
      this.payloadLength = (short) (payloadLength & 0xffff);
      return this;
    }

    public Builder nextHeader(final TransportLayer nextHeader) {
      this.nextHeader = nextHeader;
      return this;
    }

    public Builder hopLimit(final int hopLimit) {
      this.hopLimit = (byte) (hopLimit & 0xff);
      return this;
    }

    public Builder sourceAddress(final Inet6Address sourceAddress) {
      this.sourceAddress = sourceAddress;
      return this;
    }

    public Builder destinationAddress(final Inet6Address destinationAddress) {
      this.destinationAddress = destinationAddress;
      return this;
    }

    public Builder payloadBuffer(final Memory buffer) {
      this.payloadBuffer = buffer;
      return this;
    }

    @Override
    public Packet build() {
      return new Ip6(this);
    }

    @Override
    public Packet build(final Memory buffer) {
      resetIndex(buffer);
      int iscratch = buffer.readInt();
      this.trafficClass = (byte) (iscratch >> 20 & 0xff);
      this.flowLabel = iscratch & 0xfffff;
      this.payloadLength = buffer.readShort();
      this.nextHeader = TransportLayer.valueOf(buffer.readByte());
      this.hopLimit = buffer.readByte();
      byte[] addrBuf = new byte[Inet6Address.IPV6_ADDRESS_LENGTH];
      buffer.readBytes(addrBuf);
      this.sourceAddress = Inet6Address.valueOf(addrBuf);
      addrBuf = new byte[Inet6Address.IPV6_ADDRESS_LENGTH];
      buffer.readBytes(addrBuf);
      this.destinationAddress = Inet6Address.valueOf(addrBuf);
      this.buffer = buffer;
      this.payloadBuffer = buffer.slice();
      return new Ip6(this);
    }

    @Override
    public void reset() {
      if (buffer != null) {
        reset(readerIndex, Header.IPV6_HEADER_LENGTH);
      }
    }

    @Override
    public void reset(int offset, int length) {
      if (buffer != null) {
        Validate.notIllegalArgument(offset + length <= buffer.capacity());
        Validate.notIllegalArgument(trafficClass >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(flowLabel >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(payloadLength >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(nextHeader != null, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(hopLimit >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(sourceAddress != null, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(destinationAddress != null, ILLEGAL_HEADER_EXCEPTION);
        int index = offset;
        int scratch = ((trafficClass << 20) & 0xff) | (flowLabel & 0xfffff);
        buffer.setInt(offset, scratch);
        index += 4;
        buffer.setShort(offset, payloadLength);
        index += 2;
        buffer.setByte(index, nextHeader.value());
        index += 1;
        buffer.setByte(index, hopLimit);
        index += 1;
        buffer.setBytes(index, sourceAddress.address());
        index += Inet6Address.IPV6_ADDRESS_LENGTH;
        buffer.setBytes(index, destinationAddress.address());
      }
    }
  }

  public abstract static class ExtensionHeader extends AbstractPacket.Header {}

  public static final TransportLayer IPV6_ROUTING =
      new TransportLayer((byte) 43, "Routing Header for IPv6.");
  public static final TransportLayer IPV6_FRAGMENT =
      new TransportLayer((byte) 44, "Fragment Header for IPv6.");
  public static final TransportLayer IPV6_HOPOPT =
      new TransportLayer((byte) 0, "IPv6 Hop by Hop NeighborDiscoveryOptions.");
  public static final TransportLayer IPV6_DSTOPT =
      new TransportLayer((byte) 60, "IPv6 Destination NeighborDiscoveryOptions.");
  public static final TransportLayer IPV6_AH =
      new TransportLayer((byte) 51, "IPv6 Authentication Header.");

  static {
    TransportLayer.register(IPV6_AH, new Authentication.Builder());
    TransportLayer.register(IPV6_DSTOPT, new DestinationOptions.Builder());
    TransportLayer.register(IPV6_ROUTING, new Routing.Builder());
    TransportLayer.register(IPV6_FRAGMENT, new Fragment.Builder());
    TransportLayer.register(IPV6_HOPOPT, new HopByHopOptions.Builder());
  }
}
