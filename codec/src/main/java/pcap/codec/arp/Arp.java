/** This code is licenced under the GPL version 2. */
package pcap.codec.arp;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import pcap.codec.AbstractPacket;
import pcap.codec.DataLinkLayer;
import pcap.codec.NetworkLayer;
import pcap.codec.Packet;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;
import pcap.common.net.Inet4Address;
import pcap.common.net.MacAddress;
import pcap.common.util.NamedNumber;
import pcap.common.util.Strings;
import pcap.common.util.Validate;

/**
 * @see <a href="https://en.wikipedia.org/wiki/Address_Resolution_Protocol">Wikipedia</a>
 * @see <a href="https://tools.ietf.org/html/rfc826">RFC</a>
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
@Inclubating
public class Arp extends AbstractPacket {

  private final Header header;
  private final Packet payload;
  private final Builder builder;

  private Arp(final Builder builder) {
    this.header = new Header(builder);
    this.payloadBuffer = builder.payloadBuffer;
    if (this.payloadBuffer != null
        && this.payloadBuffer.readerIndex() < this.payloadBuffer.writerIndex()) {
      this.payload =
          NetworkLayer.valueOf(this.header.payloadType().value()).newInstance(this.payloadBuffer);
    } else {
      this.payload = null;
    }
    this.builder = builder;
  }

  public static final Arp newPacket(final Memory buffer) {
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
        .add("header", header())
        .add("payload", payload() != null ? payload().getClass().getSimpleName() : "(None)")
        .toString();
  }

  public static final class Header extends AbstractPacket.Header {

    public static final int ARP_HEADER_LENGTH = 28;

    private final DataLinkLayer hardwareType;
    private final NetworkLayer protocolType;
    private final byte hardwareAddressLength;
    private final byte protocolAddressLength;
    private final OperationCode operationCode;
    private final MacAddress senderHardwareAddress;
    private final Inet4Address senderProtocolAddress;
    private final MacAddress targetHardwareAddress;
    private final Inet4Address targetProtocolAddress;

    private final Builder builder;

    private Header(final Builder builder) {
      this.hardwareType = builder.hardwareType;
      this.protocolType = builder.protocolType;
      this.hardwareAddressLength = builder.hardwareAddressLength;
      this.protocolAddressLength = builder.protocolAddressLength;
      this.operationCode = builder.operationCode;
      this.senderHardwareAddress = builder.senderHardwareAddress;
      this.senderProtocolAddress = builder.senderProtocolAddress;
      this.targetHardwareAddress = builder.targetHardwareAddress;
      this.targetProtocolAddress = builder.targetProtocolAddress;
      this.buffer = resetIndex(builder.buffer, length());
      this.builder = builder;
    }

    /**
     * Hardware type (HTYPE).
     *
     * <p>This field specifies the network link protocol type. Example: {@link
     * DataLinkLayer#EN10MB}.
     *
     * @return returns {@link DataLinkLayer}.
     */
    public DataLinkLayer hardwareType() {
      return hardwareType;
    }

    /**
     * Protocol type (PTYPE).
     *
     * <p>This field specifies the internetwork protocol for which the ARP request is intended. For
     * IPv4, this has the value {@link NetworkLayer#IPV4} ({@code 0x0800}). The permitted PTYPE
     * values share a numbering space with those for {@link NetworkLayer} (EtherType).
     *
     * @return returns {@link NetworkLayer}.
     */
    public NetworkLayer protocolType() {
      return protocolType;
    }

    /**
     * Hardware length (HLEN).
     *
     * <p>Length (in octets) of a hardware address. Ethernet address length is 6 ({@link
     * MacAddress#MAC_ADDRESS_LENGTH}).
     *
     * @return returns hardware address length.
     */
    public int hardwareAddressLength() {
      return hardwareAddressLength & 0xFF;
    }

    /**
     * Protocol length (PLEN).
     *
     * <p>Length (in octets) of internetwork addresses. The internetwork protocol is specified in
     * PTYPE. Example: IPv4 address length is 4 ({@link Inet4Address#IPV4_ADDRESS_LENGTH}).
     *
     * @return returns protocol address length.
     */
    public int protocolAddressLength() {
      return protocolAddressLength & 0xFF;
    }

    /**
     * Operation.
     *
     * <p>Specifies the operation that the sender is performing: {@link OperationCode#ARP_REQUEST}
     * for request, {@link OperationCode#ARP_REPLY} for reply.
     *
     * @return returns {@link OperationCode}.
     */
    public OperationCode operationCode() {
      return operationCode;
    }

    /**
     * Sender hardware address (SHA).
     *
     * <p>Media address of the sender. In an ARP request this field is used to indicate the address
     * of the host sending the request. In an ARP reply this field is used to indicate the address
     * of the host that the request was looking for.
     *
     * @return returns sender hardware address.
     */
    public MacAddress senderHardwareAddress() {
      return senderHardwareAddress;
    }

    /**
     * Sender protocol address (SHA).
     *
     * <p>Internetwork address of the sender.
     *
     * @return returns sender protocol address.
     */
    public Inet4Address senderProtocolAddress() {
      return senderProtocolAddress;
    }

    /**
     * Target hardware address (THA).
     *
     * <p>Media address of the intended receiver. In an ARP request this field is ignored. In an ARP
     * reply this field is used to indicate the address of the host that originated the ARP request.
     *
     * @return returns target hardware address.
     */
    public MacAddress targetHardwareAddress() {
      return targetHardwareAddress;
    }

    /**
     * Target protocol address (TPA).
     *
     * <p>Internetwork address of the intended receiver.
     *
     * @return returns target protocol address.
     */
    public Inet4Address targetProtocolAddress() {
      return targetProtocolAddress;
    }

    @Override
    public NetworkLayer payloadType() {
      return NetworkLayer.EMPTY;
    }

    @Override
    public int length() {
      return Header.ARP_HEADER_LENGTH;
    }

    @Override
    public Memory buffer() {
      if (buffer == null) {
        buffer = ALLOCATOR.allocate(length());
        buffer.writeShort(hardwareType.value());
        buffer.writeShort(protocolType.value());
        buffer.writeByte(hardwareAddressLength);
        buffer.writeByte(protocolAddressLength);
        buffer.writeShort(operationCode.value());
        buffer.writeBytes(senderHardwareAddress.address());
        buffer.writeBytes(senderProtocolAddress.address());
        buffer.writeBytes(targetHardwareAddress.address());
        buffer.writeBytes(targetProtocolAddress.address());
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
      return hardwareAddressLength == header.hardwareAddressLength
          && protocolAddressLength == header.protocolAddressLength
          && hardwareType.equals(header.hardwareType)
          && protocolType.equals(header.protocolType)
          && operationCode.equals(header.operationCode)
          && senderHardwareAddress.equals(header.senderHardwareAddress)
          && senderProtocolAddress.equals(header.senderProtocolAddress)
          && targetHardwareAddress.equals(header.targetHardwareAddress)
          && targetProtocolAddress.equals(header.targetProtocolAddress);
    }

    @Override
    public int hashCode() {
      return Objects.hash(
          hardwareType,
          protocolType,
          hardwareAddressLength,
          protocolAddressLength,
          operationCode,
          senderHardwareAddress,
          senderProtocolAddress,
          targetHardwareAddress,
          targetProtocolAddress);
    }

    @Override
    public String toString() {
      return Strings.toStringBuilder(this)
          .add("hardwareType", hardwareType())
          .add("protocolType", protocolType())
          .add("hardwareAddressLength", hardwareAddressLength() & 0xFF)
          .add("protocolAddressLength", protocolAddressLength() & 0xFF)
          .add("operationCode", operationCode())
          .add("senderHardwareAddress", senderHardwareAddress())
          .add("senderProtocolAddress", senderProtocolAddress())
          .add("targetHardwareAddress", targetHardwareAddress())
          .add("targetProtocolAddress", targetProtocolAddress())
          .toString();
    }
  }

  public static final class Builder extends AbstractPacket.Builder {

    private DataLinkLayer hardwareType = DataLinkLayer.EN10MB;
    private NetworkLayer protocolType = NetworkLayer.IPV4;
    private byte hardwareAddressLength = MacAddress.MAC_ADDRESS_LENGTH;
    private byte protocolAddressLength = Inet4Address.IPV4_ADDRESS_LENGTH;
    private OperationCode operationCode = OperationCode.ARP_REQUEST;
    private MacAddress senderHardwareAddress = MacAddress.ZERO;
    private Inet4Address senderProtocolAddress = Inet4Address.ZERO;
    private MacAddress targetHardwareAddress = MacAddress.ZERO;
    private Inet4Address targetProtocolAddress = Inet4Address.ZERO;

    private Memory buffer;
    private Memory payloadBuffer;

    /**
     * Hardware type (HTYPE).
     *
     * <p>This field specifies the network link protocol type. Example: {@link
     * DataLinkLayer#EN10MB}.
     *
     * @param hardwareType datalink type.
     * @return returns this {@link Builder}.
     */
    public Builder hardwareType(final DataLinkLayer hardwareType) {
      this.hardwareType = hardwareType;
      return this;
    }

    /**
     * Protocol type (PTYPE).
     *
     * <p>This field specifies the internetwork protocol for which the ARP request is intended. For
     * IPv4, this has the value {@link NetworkLayer#IPV4} ({@code 0x0800}). The permitted PTYPE
     * values share a numbering space with those for {@link NetworkLayer} (EtherType).
     *
     * @param protocolType protocol type.
     * @return returns this {@link Builder}.
     */
    public Builder protocolType(final NetworkLayer protocolType) {
      this.protocolType = protocolType;
      return this;
    }

    /**
     * Hardware length (HLEN).
     *
     * <p>Length (in octets) of a hardware address. Ethernet address length is 6 ({@link
     * MacAddress#MAC_ADDRESS_LENGTH}).
     *
     * @param hardwareAddressLength hardaware length.
     * @return returns this {@link Builder}.
     */
    public Builder hardwareAddressLength(final int hardwareAddressLength) {
      this.hardwareAddressLength = (byte) (hardwareAddressLength & 0xFF);
      return this;
    }

    /**
     * Protocol length (PLEN).
     *
     * <p>Length (in octets) of internetwork addresses. The internetwork protocol is specified in
     * PTYPE. Example: IPv4 address length is 4 ({@link Inet4Address#IPV4_ADDRESS_LENGTH}).
     *
     * @param protocolAddressLength protocol address length.
     * @return returns this {@link Builder}.
     */
    public Builder protocolAddressLength(final int protocolAddressLength) {
      this.protocolAddressLength = (byte) (protocolAddressLength & 0xFF);
      return this;
    }

    /**
     * Operation.
     *
     * <p>Specifies the operation that the sender is performing: {@link OperationCode#ARP_REQUEST}
     * for request, {@link OperationCode#ARP_REPLY} for reply.
     *
     * @param operationCode ARP operation code.
     * @return returns this {@link Builder}.
     */
    public Builder operationCode(final OperationCode operationCode) {
      this.operationCode = operationCode;
      return this;
    }

    /**
     * Sender hardware address (SHA).
     *
     * <p>Media address of the sender. In an ARP request this field is used to indicate the address
     * of the host sending the request. In an ARP reply this field is used to indicate the address
     * of the host that the request was looking for.
     *
     * @param senderHardwareAddress sender hardware address.
     * @return returns this {@link Builder}.
     */
    public Builder senderHardwareAddress(final MacAddress senderHardwareAddress) {
      this.senderHardwareAddress = senderHardwareAddress;
      return this;
    }

    /**
     * Sender protocol address (SHA).
     *
     * <p>Internetwork address of the sender.
     *
     * @param senderProtocolAddress sender protocol address.
     * @return returns this {@link Builder}.
     */
    public Builder senderProtocolAddress(final Inet4Address senderProtocolAddress) {
      this.senderProtocolAddress = senderProtocolAddress;
      return this;
    }

    /**
     * Target hardware address (THA).
     *
     * <p>Media address of the intended receiver. In an ARP request this field is ignored. In an ARP
     * reply this field is used to indicate the address of the host that originated the ARP request.
     *
     * @param targetHardwareAddress target hardware address.
     * @return returns this {@link Builder}.
     */
    public Builder targetHardwareAddress(final MacAddress targetHardwareAddress) {
      this.targetHardwareAddress = targetHardwareAddress;
      return this;
    }

    /**
     * Target protocol address (TPA).
     *
     * <p>Internetwork address of the intended receiver.
     *
     * @param targetProtocolAddress target protocol addresss.
     * @return returns this {@link Builder}.
     */
    public Builder targetProtocolAddress(final Inet4Address targetProtocolAddress) {
      this.targetProtocolAddress = targetProtocolAddress;
      return this;
    }

    @Override
    public Builder payload(AbstractPacket packet) {
      this.payloadBuffer = packet.buffer();
      return this;
    }

    @Override
    public Arp build() {
      if (buffer != null) {
        return build(buffer);
      }
      return new Arp(this);
    }

    @Override
    public Arp build(final Memory buffer) {
      resetIndex(buffer);
      this.hardwareType = DataLinkLayer.valueOf(buffer.readShort());
      this.protocolType = NetworkLayer.valueOf(buffer.readShort());
      this.hardwareAddressLength = buffer.readByte();
      this.protocolAddressLength = buffer.readByte();
      this.operationCode = OperationCode.valueOf(buffer.readShort());
      byte[] byteBuffer;
      int hardwareAddressLength = this.hardwareAddressLength & 0xFF;
      int protocolAddressLength = this.protocolAddressLength & 0xFF;
      byteBuffer = new byte[hardwareAddressLength];
      buffer.readBytes(byteBuffer);
      this.senderHardwareAddress = MacAddress.valueOf(byteBuffer);
      byteBuffer = new byte[protocolAddressLength];
      buffer.readBytes(byteBuffer);
      this.senderProtocolAddress = Inet4Address.valueOf(byteBuffer);
      byteBuffer = new byte[hardwareAddressLength];
      buffer.readBytes(byteBuffer);
      this.targetHardwareAddress = MacAddress.valueOf(byteBuffer);
      byteBuffer = new byte[protocolAddressLength];
      buffer.readBytes(byteBuffer);
      this.targetProtocolAddress = Inet4Address.valueOf(byteBuffer);
      this.buffer = buffer;
      this.payloadBuffer = buffer.slice();
      return new Arp(this);
    }

    @Override
    public Builder reset() {
      return reset(readerIndex, Header.ARP_HEADER_LENGTH);
    }

    @Override
    public Builder reset(long offset, long length) {
      if (buffer != null) {
        resetIndex(buffer);
        Validate.notIllegalArgument(offset + length <= buffer.capacity());
        Validate.notIllegalArgument(hardwareType != null, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(protocolType != null, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument((hardwareAddressLength & 0xFF) != 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument((protocolAddressLength & 0xFF) != 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(senderHardwareAddress != null, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(senderProtocolAddress != null, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(targetHardwareAddress != null, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(targetProtocolAddress != null, ILLEGAL_HEADER_EXCEPTION);
        long index = offset;
        buffer.setShort(index, hardwareType.value());
        index += 2;
        buffer.setShort(index, protocolType.value());
        index += 2;
        buffer.setByte(index, hardwareAddressLength);
        index += 1;
        buffer.setByte(index, protocolAddressLength);
        index += 1;
        buffer.setShort(index, operationCode.value());
        index += 2;
        buffer.setBytes(index, senderHardwareAddress.address());
        index += MacAddress.MAC_ADDRESS_LENGTH;
        buffer.setBytes(index, senderProtocolAddress.address());
        index += Inet4Address.IPV4_ADDRESS_LENGTH;
        buffer.setBytes(index, targetHardwareAddress.address());
        index += MacAddress.MAC_ADDRESS_LENGTH;
        buffer.setBytes(index, targetProtocolAddress.address());
      }
      return this;
    }
  }

  public static final class OperationCode extends NamedNumber<Short, OperationCode> {

    public static final OperationCode ARP_REQUEST = new OperationCode((short) 0x01, "Arp Request");

    public static final OperationCode ARP_REPLY = new OperationCode((short) 0x02, "Arp Reply");

    public static final OperationCode UNKNOWN = new OperationCode((short) -1, "Unknown");

    private static final Map<Short, OperationCode> REGISTRY = new HashMap<>();

    static {
      REGISTRY.put(ARP_REQUEST.value(), ARP_REQUEST);
      REGISTRY.put(ARP_REPLY.value(), ARP_REPLY);
    }

    public OperationCode(Short value, String name) {
      super(value, name);
    }

    @Override
    public int compareTo(OperationCode o) {
      return value().compareTo(o.value());
    }

    /**
     * Add new {@link OperationCode} to registry.
     *
     * @param operationCode operation code.
     * @return returns {@link OperationCode}.
     */
    public static OperationCode register(final OperationCode operationCode) {
      return REGISTRY.put(operationCode.value(), operationCode);
    }

    /**
     * Get operation code from value.
     *
     * @param value value.
     * @return returns {@link OperationCode}.
     */
    public static OperationCode valueOf(final Short value) {
      if (REGISTRY.containsKey(value)) {
        return REGISTRY.get(value);
      } else {
        return UNKNOWN;
      }
    }

    @Override
    public String toString() {
      return super.toString();
    }
  }
}
