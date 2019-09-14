/** This code is licenced under the GPL version 2. */
package pcap.codec.ndp;

import pcap.codec.AbstractPacket;
import pcap.codec.Packet;
import pcap.codec.UnknownPacket;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;
import pcap.common.net.Inet6Address;
import pcap.common.util.NamedNumber;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class Redirect extends AbstractPacket {

  private final Header header;
  private final Packet payload;

  /**
   * Build Redirect packet.
   *
   * @param builder builder.
   */
  public Redirect(Builder builder) {
    this.header = new Header(builder);
    this.payload = null;
    this.payloadBuffer = builder.payloadBuffer;
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

    public static final byte REDIRECT_HEADER_LENGTH = 36;

    private final Inet6Address targetAddress;
    private final Inet6Address destinationAddress;

    private final NeighborDiscoveryOptions options;

    private final Builder builder;

    private Header(Builder builder) {
      this.targetAddress = builder.targetAddress;
      this.destinationAddress = builder.destinationAddress;
      this.options = builder.options;
      this.buffer = builder.buffer.slice(builder.buffer.readerIndex() - getLength(), getLength());
      this.builder = builder;
    }

    public Inet6Address getTargetAddress() {
      return targetAddress;
    }

    public Inet6Address getDestinationAddress() {
      return destinationAddress;
    }

    public NeighborDiscoveryOptions getOptions() {
      return options;
    }

    @Override
    public <T extends NamedNumber> T getPayloadType() {
      return (T) UnknownPacket.UNKNOWN_PAYLOAD_TYPE;
    }

    @Override
    public int getLength() {
      return REDIRECT_HEADER_LENGTH + options.getHeader().getLength();
    }

    @Override
    public Memory getBuffer() {
      if (buffer == null) {
        buffer = ALLOCATOR.allocate(getLength());
        buffer.writeInt(0);
        buffer.writeBytes(targetAddress.getAddress());
        buffer.writeBytes(destinationAddress.getAddress());
        buffer.writeBytes(options.getHeader().getBuffer());
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
          .append("\ttargetAddress: ")
          .append(targetAddress)
          .append('\n')
          .append("\tdestinationAddress: ")
          .append(destinationAddress)
          .append('\n')
          .append("\toptions: ")
          .append(options)
          .append('\n')
          .toString();
    }
  }

  @Override
  public String toString() {
    return new StringBuilder("[ Redirect Header (")
        .append(getHeader().getLength())
        .append(" bytes) ]")
        .append('\n')
        .append(header)
        .append("\tpayload: ")
        .append(payload != null ? payload.getClass().getSimpleName() : "")
        .toString();
  }

  public static class Builder extends AbstractPacket.Builder {

    private Inet6Address targetAddress;
    private Inet6Address destinationAddress;

    private NeighborDiscoveryOptions options;

    private Memory buffer;
    private Memory payloadBuffer;

    public Builder targetAddrss(Inet6Address targetAddress) {
      this.targetAddress = targetAddress;
      return this;
    }

    public Builder destinationAddress(Inet6Address destinationAddress) {
      this.destinationAddress = destinationAddress;
      return this;
    }

    @Override
    public Packet build() {
      return new Redirect(this);
    }

    @Override
    public Packet build(Memory buffer) {
      buffer.readInt();
      byte[] target = new byte[Inet6Address.IPV6_ADDRESS_LENGTH];
      buffer.readBytes(target);
      this.targetAddress = Inet6Address.valueOf(target);
      byte[] destination = new byte[Inet6Address.IPV6_ADDRESS_LENGTH];
      buffer.readBytes(destination);
      this.destinationAddress = Inet6Address.valueOf(destination);
      this.options =
          (NeighborDiscoveryOptions) new NeighborDiscoveryOptions.Builder().build(buffer);
      this.buffer = buffer;
      this.payloadBuffer = buffer.slice();
      return new Redirect(this);
    }
  }
}
