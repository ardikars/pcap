/** This code is licenced under the GPL version 2. */
package pcap.codec.ethernet;

import pcap.codec.AbstractPacket;
import pcap.codec.NetworkLayer;
import pcap.codec.Packet;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;
import pcap.common.net.MacAddress;
import pcap.common.util.Validate;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class Ethernet extends AbstractPacket {

  private final Header header;
  private final Packet payload;

  private Ethernet(final Builder builder) {
    this.header = new Header(builder);
    this.payloadBuffer = builder.payloadBuffer;
    if (this.payloadBuffer != null) {
      this.payload =
          NetworkLayer.valueOf(this.header.getPayloadType().getValue())
              .newInstance(this.payloadBuffer);
    } else {
      this.payload = null;
    }
  }

  public static final Ethernet newPacket(final Memory buffer) {
    return new Builder().build(buffer);
  }

  @Override
  public Header getHeader() {
    return header;
  }

  @Override
  public Packet getPayload() {
    return payload;
  }

  public static class Header extends AbstractPacket.Header {

    public static final int ETHERNET_HEADER_LENGTH = 14;

    private final MacAddress destinationMacAddress;
    private final MacAddress sourceMacAddress;
    private final NetworkLayer ethernetType;

    private final Builder builder;

    private Header(final Builder builder) {
      this.destinationMacAddress = builder.destinationMacAddress;
      this.sourceMacAddress = builder.sourceMacAddress;
      this.ethernetType = builder.ethernetType;
      this.buffer = slice(builder.buffer, getLength());
      this.builder = builder;
    }

    public MacAddress getDestinationMacAddress() {
      return destinationMacAddress;
    }

    public MacAddress getSourceMacAddress() {
      return sourceMacAddress;
    }

    public NetworkLayer getEthernetType() {
      return ethernetType;
    }

    @Override
    public NetworkLayer getPayloadType() {
      return ethernetType;
    }

    @Override
    public int getLength() {
      return Header.ETHERNET_HEADER_LENGTH;
    }

    @Override
    public Memory getBuffer() {
      if (buffer == null) {
        buffer = ALLOCATOR.allocate(getLength());
        buffer.writeBytes(destinationMacAddress.toBytes());
        buffer.writeBytes(sourceMacAddress.toBytes());
        buffer.writeShort(ethernetType.getValue());
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
          .append("\tdestinationMacAddress: ")
          .append(destinationMacAddress)
          .append('\n')
          .append("\tsourceMacAddress: ")
          .append(sourceMacAddress)
          .append('\n')
          .append("\tethernetType: ")
          .append(ethernetType)
          .append('\n')
          .toString();
    }
  }

  @Override
  public String toString() {
    return new StringBuilder("[ Ethernet Header (")
        .append(getHeader().getLength())
        .append(" bytes) ]")
        .append('\n')
        .append(header)
        .append("\tpayload: ")
        .append(payload != null ? payload.getClass().getSimpleName() : "")
        .toString();
  }

  public static class Builder extends AbstractPacket.Builder {

    private MacAddress destinationMacAddress;
    private MacAddress sourceMacAddress;
    private NetworkLayer ethernetType;

    private Memory buffer;
    private Memory payloadBuffer;

    public Builder destinationMacAddress(final MacAddress destinationMacAddress) {
      this.destinationMacAddress = destinationMacAddress;
      return this;
    }

    public Builder sourceMacAddress(final MacAddress sourceMacAddress) {
      this.sourceMacAddress = sourceMacAddress;
      return this;
    }

    public Builder ethernetType(final NetworkLayer ethernetType) {
      this.ethernetType = ethernetType;
      return this;
    }

    public Builder payloadBuffer(final Memory buffer) {
      this.payloadBuffer = buffer;
      return this;
    }

    @Override
    public Ethernet build() {
      return new Ethernet(this);
    }

    @Override
    public Ethernet build(final Memory buffer) {
      byte[] hardwareAddressBuffer;
      hardwareAddressBuffer = new byte[MacAddress.MAC_ADDRESS_LENGTH];
      buffer.readBytes(hardwareAddressBuffer);
      this.destinationMacAddress = MacAddress.valueOf(hardwareAddressBuffer);
      hardwareAddressBuffer = new byte[MacAddress.MAC_ADDRESS_LENGTH];
      buffer.readBytes(hardwareAddressBuffer);
      this.sourceMacAddress = MacAddress.valueOf(hardwareAddressBuffer);
      this.ethernetType = NetworkLayer.valueOf(buffer.readShort());
      this.buffer = buffer;
      this.payloadBuffer = buffer.slice();
      return new Ethernet(this);
    }

    @Override
    public void reset() {
      if (buffer != null) {
        reset(0, Header.ETHERNET_HEADER_LENGTH);
      }
    }

    @Override
    public void reset(int offset, int length) {
      if (buffer != null) {
        Validate.notIllegalArgument(offset + length <= buffer.capacity());
        Validate.notIllegalArgument(destinationMacAddress != null, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(sourceMacAddress != null, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(ethernetType != null, ILLEGAL_HEADER_EXCEPTION);
        int index = offset;
        buffer.setBytes(index, destinationMacAddress.toBytes());
        index += MacAddress.MAC_ADDRESS_LENGTH;
        buffer.setBytes(index, sourceMacAddress.toBytes());
        index += MacAddress.MAC_ADDRESS_LENGTH;
        buffer.setShort(index, ethernetType.getValue());
      }
    }
  }
}
