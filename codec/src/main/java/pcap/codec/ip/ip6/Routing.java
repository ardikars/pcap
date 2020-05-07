/** This code is licenced under the GPL version 2. */
package pcap.codec.ip.ip6;

import java.util.HashMap;
import java.util.Map;
import pcap.codec.AbstractPacket;
import pcap.codec.Packet;
import pcap.codec.TransportLayer;
import pcap.codec.ip.Ip6;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;
import pcap.common.util.NamedNumber;
import pcap.common.util.Strings;
import pcap.common.util.Validate;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class Routing extends AbstractPacket {

  private final Header header;
  private final Packet payload;
  private final Builder builder;

  private Routing(final Builder builder) {
    this.header = new Header(builder);
    this.payloadBuffer = builder.payloadBuffer;
    if (this.payloadBuffer != null) {
      this.payload =
          TransportLayer.valueOf(header.payloadType().value()).newInstance(this.payloadBuffer);
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

  public static final class Header extends Ip6.ExtensionHeader {

    public static final int FIXED_ROUTING_HEADER_LENGTH = 4;
    public static final int FIXED_ROUTING_DATA_LENGTH = 4;

    private final TransportLayer nextHeader;
    private final byte extensionLength;
    private final Type routingType;
    private final byte segmentLeft;

    private final byte[] routingData;

    private final Builder builder;

    private Header(final Builder builder) {
      this.nextHeader = builder.nextHeader;
      this.extensionLength = builder.extensionLength;
      this.routingType = builder.routingType;
      this.segmentLeft = builder.segmentLeft;
      this.routingData = builder.routingData;
      this.buffer = slice(builder.buffer, length());
      this.builder = builder;
    }

    public TransportLayer nextHeader() {
      return nextHeader;
    }

    public int extensionLength() {
      return extensionLength & 0xff;
    }

    public Type routingType() {
      return routingType;
    }

    public int segmentLeft() {
      return segmentLeft & 0xff;
    }

    public byte[] routingData() {
      byte[] routingData = new byte[this.routingData.length];
      System.arraycopy(this.routingData, 0, routingData, 0, routingData.length);
      return routingData;
    }

    @Override
    public TransportLayer payloadType() {
      return nextHeader;
    }

    @Override
    public int length() {
      return FIXED_ROUTING_HEADER_LENGTH + (routingData == null ? 0 : routingData.length);
    }

    @Override
    public Memory buffer() {
      if (buffer == null) {
        buffer = ALLOCATOR.allocate(length());
        buffer.writeByte(nextHeader.value());
        buffer.writeByte(extensionLength);
        buffer.writeByte(routingType.value());
        buffer.writeByte(segmentLeft);
        if (routingData != null) {
          buffer.writeBytes(routingData);
        }
      }
      return buffer;
    }

    @Override
    public String toString() {
      return Strings.toStringBuilder(this)
          .add("nextHeader", nextHeader)
          .add("extensionLength", extensionLength)
          .add("routingType", routingType)
          .add("segmentLeft", segmentLeft)
          .add("routingData", Strings.hex(routingData))
          .toString();
    }

    @Override
    public Builder builder() {
      return builder;
    }
  }

  public static final class Builder extends AbstractPacket.Builder {

    private TransportLayer nextHeader;
    private byte extensionLength;
    private Type routingType;
    private byte segmentLeft;

    private byte[] routingData;

    private Memory buffer;
    private Memory payloadBuffer;

    public Builder nextHeader(final TransportLayer nextHeader) {
      this.nextHeader = nextHeader;
      return this;
    }

    public Builder extensionLength(final int extensionLength) {
      this.extensionLength = (byte) (extensionLength & 0xff);
      return this;
    }

    public Builder routingType(final Type routingType) {
      this.routingType = routingType;
      return this;
    }

    public Builder segmentLeft(final int segmentLeft) {
      this.segmentLeft = (byte) (segmentLeft & 0xff);
      return this;
    }

    /**
     * Add routing data.
     *
     * @param routingData routing data.
     * @return returns this {@link Builder} object.
     */
    public Builder routingData(final byte[] routingData) {
      this.routingData = new byte[routingData.length];
      System.arraycopy(routingData, 0, this.routingData, 0, this.routingData.length);
      return this;
    }

    @Override
    public Routing build() {
      return new Routing(this);
    }

    @Override
    public Routing build(final Memory buffer) {
      resetIndex(buffer);
      this.nextHeader = TransportLayer.valueOf(buffer.readByte());
      this.extensionLength = buffer.readByte();
      this.routingType = Type.valueOf(buffer.readByte());
      this.segmentLeft = buffer.readByte();
      this.routingData = new byte[Header.FIXED_ROUTING_DATA_LENGTH + 8 * this.extensionLength];
      buffer.readBytes(this.routingData);
      this.buffer = buffer;
      this.payloadBuffer = buffer.slice();
      return new Routing(this);
    }

    @Override
    public Builder reset() {
      return reset(readerIndex, Header.FIXED_ROUTING_HEADER_LENGTH + routingData.length);
    }

    @Override
    public Builder reset(int offset, int length) {
      if (buffer != null) {
        Validate.notIllegalArgument(offset + length <= buffer.capacity());
        Validate.notIllegalArgument(nextHeader != null, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(extensionLength >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(routingType != null, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(segmentLeft >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(routingData != null, ILLEGAL_HEADER_EXCEPTION);
        int index = offset;
        buffer.setByte(index, nextHeader.value());
        index += 1;
        buffer.setByte(index, extensionLength);
        index += 1;
        buffer.setByte(index, routingType.value());
        index += 1;
        buffer.setByte(index, segmentLeft);
        index += 1;
        buffer.setBytes(index, routingData);
      }
      return this;
    }
  }

  public static final class Type extends NamedNumber<Byte, Type> {

    public static final Type UNKNOWN = new Type((byte) -1, "UNKNOWN.");

    public static final Type DEPRECATED_01 =
        new Type(
            (byte) 0,
            "Due to the fact that with Routing HeaderAbstract type 0 a simple but effective[15]"
                + " denial-of-service attack could be launched, this header is deprecated since 2007[16]"
                + " and host and routers are required to ignore these headers.");

    public static final Type DEPRECATED_02 =
        new Type(
            (byte) 1,
            "Used for the Nimrod[17] project funded by DARPA. It is deprecated since 2009.");

    public static final Type ALLOWED_01 =
        new Type(
            (byte) 2,
            "A limited version of type 0 and is used for Mobile IPv6, where it can hold the Home Address of the Mobile Node.");

    public static final Type ALLOWED_02 =
        new Type((byte) 3, "RPL Source Route HeaderAbstract[18] for Low-Power and Lossy Networks.");

    public static final Type PRIVATE_USE_01 =
        new Type(
            (byte) 253,
            "May be used for testing, not for actual implementations. RFC3692-style Experiment 1.[13]");

    public static final Type PRIVATE_USE_02 =
        new Type(
            (byte) 254,
            "May be used for testing, not for actual implementations. RFC3692-style Experiment 2.[13]");

    private static Map<Byte, Type> REGISTRY = new HashMap<>();

    static {
      REGISTRY.put(DEPRECATED_01.value(), DEPRECATED_01);
      REGISTRY.put(DEPRECATED_02.value(), DEPRECATED_02);
      REGISTRY.put(ALLOWED_01.value(), ALLOWED_01);
      REGISTRY.put(ALLOWED_02.value(), ALLOWED_02);
      REGISTRY.put(PRIVATE_USE_01.value(), PRIVATE_USE_01);
      REGISTRY.put(PRIVATE_USE_02.value(), PRIVATE_USE_02);
    }

    protected Type(Byte value, String name) {
      super(value, name);
    }

    /**
     * Get routing type from value.
     *
     * @param value value.
     * @return returns {@link Type}.
     */
    public static Type valueOf(final byte value) {
      Type type = REGISTRY.get(value);
      if (type == null) {
        return UNKNOWN;
      }
      return type;
    }

    /**
     * Add new routing type to registry.
     *
     * @param type routing type.
     * @return returns {@link Type}.
     */
    public static Type register(final Type type) {
      REGISTRY.put(type.value(), type);
      return type;
    }
  }
}
