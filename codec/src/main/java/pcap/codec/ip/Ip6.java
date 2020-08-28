/** This code is licenced under the GPL version 2. */
package pcap.codec.ip;

import java.util.Objects;
import pcap.codec.AbstractPacket;
import pcap.codec.Packet;
import pcap.codec.TransportLayer;
import pcap.codec.ip.ip6.*;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;
import pcap.common.net.Inet6Address;
import pcap.common.util.Strings;
import pcap.common.util.Validate;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class Ip6 extends Ip {

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

  private final Header header;
  private final Packet payload;
  private final Builder builder;

  private Ip6(final Builder builder) {
    this.header = new Header(builder);
    this.payloadBuffer = builder.payloadBuffer;
    if (this.payloadBuffer != null
        && this.payloadBuffer.readerIndex() < this.payloadBuffer.writerIndex()) {
      this.payload =
          TransportLayer.valueOf(this.header.payloadType().value()).newInstance(this.payloadBuffer);
    } else {
      this.payload = null;
    }
    this.builder = builder;
  }

  public static Ip6 newPacket(Memory buffer) {
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
  public Memory buffer() {
    return header().buffer();
  }

  @Override
  public Builder builder() {
    return builder;
  }

  @Override
  public String toString() {
    return Strings.toStringBuilder(this)
        .add("header", header)
        .add("payload", payload != null ? payload.getClass().getSimpleName() : "(None)")
        .toString();
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
      this.buffer = resetIndex(builder.buffer, length());
      this.builder = builder;
    }

    /**
     * Traffic class.
     *
     * @return returns traffic class.
     */
    public int trafficClass() {
      return trafficClass & 0xff;
    }

    /**
     * Flow label.
     *
     * @return returns flow label.
     */
    public int flowLabel() {
      return flowLabel & 0xfffff;
    }

    /**
     * Payload length.
     *
     * @return returns payload length.
     */
    public int payloadLength() {
      return payloadLength & 0xffff;
    }

    /**
     * Next protocol type.
     *
     * @return returns {@link TransportLayer}.
     */
    public TransportLayer nextHeader() {
      return nextHeader;
    }

    /**
     * Hop limit.
     *
     * @return returns hop limit.
     */
    public int hopLimit() {
      return hopLimit & 0xff;
    }

    /**
     * Source address.
     *
     * @return source address.
     */
    public Inet6Address sourceAddress() {
      return sourceAddress;
    }

    /**
     * Destination address.
     *
     * @return destination address.
     */
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
    public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;
      Header header = (Header) o;
      return trafficClass == header.trafficClass
          && flowLabel == header.flowLabel
          && payloadLength == header.payloadLength
          && hopLimit == header.hopLimit
          && nextHeader.equals(header.nextHeader)
          && sourceAddress.equals(header.sourceAddress)
          && destinationAddress.equals(header.destinationAddress);
    }

    @Override
    public int hashCode() {
      return Objects.hash(
          trafficClass,
          flowLabel,
          payloadLength,
          nextHeader,
          hopLimit,
          sourceAddress,
          destinationAddress);
    }

    @Override
    public String toString() {
      return Strings.toStringBuilder(this)
          .add("version", version)
          .add("trafficClass", trafficClass & 0xFF)
          .add("flowLabel", flowLabel)
          .add("payloadLength", payloadLength)
          .add("nextHeader", nextHeader)
          .add("hopLimit", hopLimit)
          .add("sourceAddress", sourceAddress)
          .add("destinationAddress", destinationAddress)
          .toString();
    }
  }

  public static final class Builder extends AbstractPaketBuilder {

    static {
      TransportLayer.register(IPV6_AH, new Authentication.Builder());
      TransportLayer.register(IPV6_DSTOPT, new DestinationOptions.Builder());
      TransportLayer.register(IPV6_FRAGMENT, new Fragment.Builder());
      TransportLayer.register(IPV6_HOPOPT, new HopByHopOptions.Builder());
      TransportLayer.register(IPV6_ROUTING, new Routing.Builder());
    }

    private byte trafficClass;
    private int flowLabel;
    private short payloadLength;
    private TransportLayer nextHeader;
    private byte hopLimit;
    private Inet6Address sourceAddress;
    private Inet6Address destinationAddress;
    private Memory buffer;
    private Memory payloadBuffer;

    public Builder() {
      this.nextHeader = TransportLayer.TCP;
      this.sourceAddress = Inet6Address.ZERO;
      this.destinationAddress = Inet6Address.ZERO;
    }

    /**
     * Traffic class.
     *
     * @param trafficClass traffic class.
     * @return returns this {@link Builder}.
     */
    public Builder trafficClass(final int trafficClass) {
      this.trafficClass = (byte) (trafficClass & 0xff);
      return this;
    }

    /**
     * Flow label.
     *
     * @param flowLabel flow label.
     * @return returns this {@link Builder}.
     */
    public Builder flowLabel(final int flowLabel) {
      this.flowLabel = flowLabel & 0xfffff;
      return this;
    }

    /**
     * Payload length.
     *
     * @param payloadLength payload length.
     * @return returns this {@link Builder}.
     */
    public Builder payloadLength(final int payloadLength) {
      this.payloadLength = (short) (payloadLength & 0xffff);
      return this;
    }

    /**
     * Next protocol type.
     *
     * @param nextHeader next header.
     * @return returns this {@link Builder}.
     */
    public Builder nextHeader(final TransportLayer nextHeader) {
      this.nextHeader = nextHeader;
      return this;
    }

    /**
     * Hop limit.
     *
     * @param hopLimit hop limit.
     * @return return this {@link Builder}.
     */
    public Builder hopLimit(final int hopLimit) {
      this.hopLimit = (byte) (hopLimit & 0xff);
      return this;
    }

    /**
     * Source address.
     *
     * @param sourceAddress source address.
     * @return returns this {@link Builder}.
     */
    public Builder sourceAddress(final Inet6Address sourceAddress) {
      this.sourceAddress = sourceAddress;
      return this;
    }

    /**
     * Destination address.
     *
     * @param destinationAddress destination address.
     * @return returns this {@link Builder}.
     */
    public Builder destinationAddress(final Inet6Address destinationAddress) {
      this.destinationAddress = destinationAddress;
      return this;
    }

    @Override
    public Builder payload(AbstractPacket packet) {
      this.payloadBuffer = packet.buffer();
      return this;
    }

    @Override
    public Ip6 build() {
      if (buffer != null) {
        return build(buffer);
      }
      return new Ip6(this);
    }

    @Override
    public Ip6 build(final Memory buffer) {
      resetIndex(buffer);
      int iscratch = buffer.readInt();
      this.trafficClass = (byte) (iscratch >> 20 & 0xFF);
      this.flowLabel = iscratch & 0xFFFFF;
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
    public Builder reset() {
      return reset(readerIndex, Header.IPV6_HEADER_LENGTH);
    }

    @Override
    public Builder reset(long offset, long length) {
      if (buffer != null) {
        resetIndex(buffer);
        Validate.notIllegalArgument(offset + length <= buffer.capacity());
        Validate.notIllegalArgument((trafficClass & 0xFF) >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument((flowLabel & 0xFFFFF) >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument((payloadLength & 0xFFFF) >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(nextHeader != null, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument((hopLimit & 0xFF) >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(sourceAddress != null, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(destinationAddress != null, ILLEGAL_HEADER_EXCEPTION);
        long index = offset;
        buffer.setInt(index, (6 & 0xF) << 28 | (trafficClass & 0xFF) << 20 | flowLabel & 0xFFFFF);
        index += 4;
        buffer.setShort(index, payloadLength);
        index += 2;
        buffer.setByte(index, nextHeader.value());
        index += 1;
        buffer.setByte(index, hopLimit);
        index += 1;
        buffer.setBytes(index, sourceAddress.address());
        index += Inet6Address.IPV6_ADDRESS_LENGTH;
        buffer.setBytes(index, destinationAddress.address());
      }
      return this;
    }
  }

  public abstract static class ExtensionHeader extends AbstractPacket.Header {}
}
