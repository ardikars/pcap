/** This code is licenced under the GPL version 2. */
package pcap.codec.ndp;

import pcap.codec.AbstractPacket;
import pcap.codec.Packet;
import pcap.codec.UnknownPacket;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;
import pcap.common.util.NamedNumber;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class RouterSolicitation extends AbstractPacket {

  private final Header header;
  private final Packet payload;

  /**
   * Builde Router Solicitation packet.
   *
   * @param builder builder.
   */
  public RouterSolicitation(Builder builder) {
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
                0, ROUTER_SOLICITATION_HEADER_LENGTH + options.getHeader().getLength());
      }
      this.builder = builder;
    }

    public NeighborDiscoveryOptions getOptions() {
      return options;
    }

    @SuppressWarnings("TypeParameterUnusedInFormals")
    @Override
    public <T extends NamedNumber> T getPayloadType() {
      return (T) UnknownPacket.UNKNOWN_PAYLOAD_TYPE;
    }

    @Override
    public int getLength() {
      return ROUTER_SOLICITATION_HEADER_LENGTH + options.getHeader().getLength();
    }

    @Override
    public Memory getBuffer() {
      if (buffer == null) {
        buffer = ALLOCATOR.allocate(getLength());
        buffer.writeInt(0);
        buffer.writeBytes(options.getHeader().getBuffer());
      }
      return buffer;
    }

    @Override
    public AbstractPacket.Builder getBuilder() {
      return builder;
    }

    @Override
    public String toString() {
      return new StringBuilder().append("\toptions: ").append(options).append('\n').toString();
    }
  }

  @Override
  public String toString() {
    return new StringBuilder("[ RouterSolicitation Header (")
        .append(getHeader().getLength())
        .append(" bytes) ]")
        .append('\n')
        .append(header)
        .append("\tpayload: ")
        .append(payload != null ? payload.getClass().getSimpleName() : "")
        .toString();
  }

  public static class Builder extends AbstractPacket.Builder {

    private NeighborDiscoveryOptions options;

    private Memory buffer;
    private Memory payloadBuffer;

    public Builder options(NeighborDiscoveryOptions options) {
      this.options = options;
      return this;
    }

    @Override
    public Packet build() {
      return new RouterSolicitation(this);
    }

    @Override
    public Packet build(Memory buffer) {
      buffer.readInt();
      this.options =
          (NeighborDiscoveryOptions) new NeighborDiscoveryOptions.Builder().build(buffer);
      this.buffer = buffer;
      this.payloadBuffer = buffer.slice();
      return new RouterSolicitation(this);
    }
  }
}
