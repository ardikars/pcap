/** This code is licenced under the GPL version 2. */
package pcap.codec.ndp;

import pcap.codec.AbstractPacket;
import pcap.codec.Packet;
import pcap.codec.UnknownPacket;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;
import pcap.common.net.Inet6Address;
import pcap.common.util.NamedNumber;
import pcap.common.util.Strings;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class Redirect extends AbstractPacket {

  private final Header header;
  private final Packet payload;
  private final Builder builder;

  /**
   * Build Redirect packet.
   *
   * @param builder builder.
   */
  public Redirect(Builder builder) {
    this.header = new Header(builder);
    this.payload = null;
    this.payloadBuffer = builder.payloadBuffer;
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
        .add("payload", payload == null ? payload.getClass().getSimpleName() : "(None)")
        .toString();
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
      this.buffer = slice(builder.buffer, length());
      this.builder = builder;
    }

    public Inet6Address targetAddress() {
      return targetAddress;
    }

    public Inet6Address destinationAddress() {
      return destinationAddress;
    }

    public NeighborDiscoveryOptions options() {
      return options;
    }

    @SuppressWarnings("TypeParameterUnusedInFormals")
    @Override
    public <T extends NamedNumber> T payloadType() {
      return (T) UnknownPacket.UNKNOWN_PAYLOAD_TYPE;
    }

    @Override
    public int length() {
      return REDIRECT_HEADER_LENGTH + options.header().length();
    }

    @Override
    public Memory buffer() {
      if (buffer == null) {
        buffer = ALLOCATOR.allocate(length());
        buffer.writeInt(0);
        buffer.writeBytes(targetAddress.address());
        buffer.writeBytes(destinationAddress.address());
        buffer.writeBytes(options.header().buffer());
      }
      return buffer;
    }

    @Override
    public Builder builder() {
      return builder;
    }

    @Override
    public String toString() {
      return Strings.toStringBuilder(this)
          .add("targetAddress", targetAddress)
          .add("destinationAddress", destinationAddress)
          .add("options", options)
          .toString();
    }
  }

  public static class Builder extends AbstractPacket.Builder {

    private Inet6Address targetAddress = Inet6Address.ZERO;
    private Inet6Address destinationAddress = Inet6Address.ZERO;

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
      resetIndex(buffer);
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
