/** This code is licenced under the GPL version 2. */
package pcap.codec.ndp;

import pcap.codec.AbstractPacket;
import pcap.codec.Packet;
import pcap.codec.UnknownPacket;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;
import pcap.common.util.NamedNumber;
import pcap.common.util.Strings;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class RouterSolicitation extends AbstractPacket {

  private final Header header;
  private final Packet payload;
  private final Builder builder;

  /**
   * Builde Router Solicitation packet.
   *
   * @param builder builder.
   */
  public RouterSolicitation(Builder builder) {
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
        .add("payload", payload != null ? payload.getClass().getSimpleName() : "(None)")
        .toString();
  }

  public static class Header extends AbstractPacket.Header {

    public static final int ROUTER_SOLICITATION_HEADER_LENGTH = 4;

    private final NeighborDiscoveryOptions options;

    private final Builder builder;

    /**
     * Builde Router Solicitation packet.
     *
     * @param builder builder.
     */
    public Header(Builder builder) {
      this.options = builder.options;
      if (builder.buffer != null) {
        this.buffer =
            builder.buffer.slice(
                0, (long) ROUTER_SOLICITATION_HEADER_LENGTH + (long) options.header().length());
      }
      this.builder = builder;
    }

    /**
     * Options.
     *
     * @return returns options.
     */
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
      return ROUTER_SOLICITATION_HEADER_LENGTH + options.header().length();
    }

    @Override
    public Memory buffer() {
      if (buffer == null) {
        buffer = ALLOCATOR.allocate(length());
        buffer.writeInt(0);
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
      return Strings.toStringBuilder(this).add("options", options).toString();
    }
  }

  public static class Builder extends AbstractPacket.Builder {

    private NeighborDiscoveryOptions options;

    private Memory buffer;
    private Memory payloadBuffer;

    /**
     * Options.
     *
     * @param options options.
     * @return returns this {@link Builder}.
     */
    public Builder options(NeighborDiscoveryOptions options) {
      this.options = options;
      return this;
    }

    @Override
    public Builder payload(AbstractPacket packet) {
      this.payloadBuffer = packet.buffer();
      return this;
    }

    @Override
    public Packet build() {
      return new RouterSolicitation(this);
    }

    @Override
    public Packet build(Memory buffer) {
      resetIndex(buffer);
      buffer.readInt();
      this.options =
          (NeighborDiscoveryOptions) new NeighborDiscoveryOptions.Builder().build(buffer);
      this.buffer = buffer;
      this.payloadBuffer = buffer.slice();
      return new RouterSolicitation(this);
    }
  }
}
