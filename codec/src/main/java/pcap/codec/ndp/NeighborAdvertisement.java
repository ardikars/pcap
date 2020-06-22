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
public class NeighborAdvertisement extends AbstractPacket {

  private final Header header;
  private final Packet payload;
  private final Builder builder;

  /**
   * Build Neighbor Advertisement packet.
   *
   * @param builder build.
   */
  public NeighborAdvertisement(Builder builder) {
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

  public static final class Header extends AbstractPacket.Header {

    public static final int HEADER_LENGTH = 20;

    private final boolean routerFlag;
    private final boolean solicitedFlag;
    private final boolean overrideFlag;
    private final Inet6Address targetAddress;

    private final NeighborDiscoveryOptions options;

    private final Builder builder;

    private Header(Builder builder) {
      this.routerFlag = builder.routerFlag;
      this.solicitedFlag = builder.solicitedFlag;
      this.overrideFlag = builder.overrideFlag;
      this.targetAddress = builder.targetAddress;
      this.options = builder.options;
      this.buffer = resetIndex(builder.buffer, length());
      this.builder = builder;
    }

    /**
     * Is router flag.
     *
     * @return returns router flag.
     */
    public boolean isRouterFlag() {
      return routerFlag;
    }

    /**
     * Is solicited flag.
     *
     * @return returns solicited flag.
     */
    public boolean isSolicitedFlag() {
      return solicitedFlag;
    }

    /**
     * Is override flag.
     *
     * @return returns override flag.
     */
    public boolean isOverrideFlag() {
      return overrideFlag;
    }

    /**
     * Target address.
     *
     * @return returns target address.
     */
    public Inet6Address targetAddress() {
      return targetAddress;
    }

    /**
     * Options.
     *
     * @return returns options.
     */
    public NeighborDiscoveryOptions options() {
      return options;
    }

    @Override
    @SuppressWarnings("TypeParameterUnusedInFormals")
    public <T extends NamedNumber> T payloadType() {
      return (T) UnknownPacket.UNKNOWN_PAYLOAD_TYPE;
    }

    @Override
    public int length() {
      return HEADER_LENGTH + options.header().length();
    }

    @Override
    public Memory buffer() {
      if (buffer == null) {
        buffer = ALLOCATOR.allocate(length());
        buffer.writeInt(
            (routerFlag ? 1 : 0) << 31
                | (solicitedFlag ? 1 : 0) << 30
                | (overrideFlag ? 1 : 0) << 29);
        buffer.writeBytes(targetAddress.address());
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
          .add("routerFlag", routerFlag)
          .add("solicitedFlag", solicitedFlag)
          .add("overrideFlag", overrideFlag)
          .add("targetAddress", targetAddress)
          .add("options", options)
          .toString();
    }
  }

  public static class Builder extends AbstractPacket.Builder {

    private boolean routerFlag;
    private boolean solicitedFlag;
    private boolean overrideFlag;
    private Inet6Address targetAddress = Inet6Address.ZERO;

    private NeighborDiscoveryOptions options;

    private Memory buffer;
    private Memory payloadBuffer;

    /**
     * Router flag.
     *
     * @param routerFlag router flag.
     * @return returns this {@link Builder}.
     */
    public Builder routerFlag(boolean routerFlag) {
      this.routerFlag = routerFlag;
      return this;
    }

    /**
     * Solicited flag.
     *
     * @param solicitedFlag solicited flag.
     * @return returns this {@link Builder}.
     */
    public Builder solicitedFlag(boolean solicitedFlag) {
      this.solicitedFlag = solicitedFlag;
      return this;
    }

    /**
     * Override flag.
     *
     * @param overrideFlag override flag.
     * @return returns this {@link Builder}.
     */
    public Builder overrideFlag(boolean overrideFlag) {
      this.overrideFlag = overrideFlag;
      return this;
    }

    /**
     * Target address.
     *
     * @param targetAddress target address.
     * @return returns this {@link Builder}.
     */
    public Builder targetAddress(Inet6Address targetAddress) {
      this.targetAddress = targetAddress;
      return this;
    }

    /**
     * Neighbor discovery options.
     *
     * @param options Neighbor discovery options.
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
      return new NeighborAdvertisement(this);
    }

    @Override
    public Packet build(Memory buffer) {
      resetIndex(buffer);
      int iscratch = buffer.readInt();
      this.routerFlag = (iscratch >> 31 & 0x1) == 1;
      this.solicitedFlag = (iscratch >> 30 & 0x1) == 1;
      this.overrideFlag = (iscratch >> 29 & 0x1) == 1;
      byte[] ipv6AddrBuffer = new byte[Inet6Address.IPV6_ADDRESS_LENGTH];
      buffer.readBytes(ipv6AddrBuffer);
      this.targetAddress = Inet6Address.valueOf(ipv6AddrBuffer);
      this.options =
          (NeighborDiscoveryOptions) new NeighborDiscoveryOptions.Builder().build(buffer);
      this.buffer = buffer;
      this.payloadBuffer = buffer.slice();
      return new NeighborAdvertisement(this);
    }
  }
}
