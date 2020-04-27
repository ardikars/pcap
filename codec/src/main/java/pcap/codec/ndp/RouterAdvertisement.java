/** This code is licenced under the GPL version 2. */
package pcap.codec.ndp;

import pcap.codec.AbstractPacket;
import pcap.codec.Packet;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;
import pcap.common.util.NamedNumber;
import pcap.common.util.Strings;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class RouterAdvertisement extends AbstractPacket {

  private final Header header;
  private final Packet payload;
  private final Builder builder;

  /**
   * Builder Router Advertisement packet.
   *
   * @param builder builder.
   */
  public RouterAdvertisement(Builder builder) {
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

    public static final int ROUTER_ADVERTISEMENT_HEADER_LENGTH = 12;

    private final byte currentHopLimit;
    private final boolean manageFlag;
    private final boolean otherFlag;
    private final short routerLifetime;
    private final int reachableTime;
    private final int retransmitTimer;

    private final NeighborDiscoveryOptions options;

    private final Builder builder;

    private Header(Builder builder) {
      this.currentHopLimit = builder.currentHopLimit;
      this.manageFlag = builder.manageFlag;
      this.otherFlag = builder.otherFlag;
      this.routerLifetime = builder.routerLifetime;
      this.reachableTime = builder.reachableTime;
      this.retransmitTimer = builder.retransmitTimer;
      this.options = builder.options;
      this.buffer = slice(builder.buffer, length());
      this.builder = builder;
    }

    public int currentHopLimit() {
      return currentHopLimit & 0xff;
    }

    public boolean isManageFlag() {
      return manageFlag;
    }

    public boolean isOtherFlag() {
      return otherFlag;
    }

    public int routerLifetime() {
      return routerLifetime & 0xffff;
    }

    public int reachableTime() {
      return reachableTime;
    }

    public int retransmitTimer() {
      return retransmitTimer;
    }

    public NeighborDiscoveryOptions options() {
      return options;
    }

    @SuppressWarnings("TypeParameterUnusedInFormals")
    @Override
    public <T extends NamedNumber> T payloadType() {
      return null;
    }

    @Override
    public int length() {
      return ROUTER_ADVERTISEMENT_HEADER_LENGTH + options.header().length();
    }

    @Override
    public Memory buffer() {
      if (buffer == null) {
        buffer = ALLOCATOR.allocate(length());
        buffer.writeByte(currentHopLimit);
        buffer.writeByte((manageFlag ? 1 : 0) << 7 | (otherFlag ? 1 : 0) << 6);
        buffer.writeShort(routerLifetime);
        buffer.writeInt(reachableTime);
        buffer.writeInt(retransmitTimer);
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
          .add("currentHopLimit", currentHopLimit)
          .add("manageFlag", manageFlag)
          .add("otherFlag", otherFlag)
          .add("routerLifetime", routerLifetime)
          .add("reachableTime", reachableTime)
          .add("retransmitTimer", retransmitTimer)
          .add("options", options)
          .toString();
    }
  }

  public static class Builder extends AbstractPacket.Builder {

    private byte currentHopLimit;
    private boolean manageFlag;
    private boolean otherFlag;
    private short routerLifetime;
    private int reachableTime;
    private int retransmitTimer;

    private NeighborDiscoveryOptions options;

    private Memory buffer;
    private Memory payloadBuffer;

    public Builder currentHopLimit(int currentHopLimit) {
      this.currentHopLimit = (byte) (currentHopLimit & 0xff);
      return this;
    }

    public Builder manageFlag(boolean manageFlag) {
      this.manageFlag = manageFlag;
      return this;
    }

    public Builder otherFlag(boolean otherFlag) {
      this.otherFlag = otherFlag;
      return this;
    }

    public Builder routerLifetime(int routerLifetime) {
      this.routerLifetime = (short) (routerLifetime & 0xffff);
      return this;
    }

    public Builder reachableTime(int reachableTime) {
      this.reachableTime = reachableTime;
      return this;
    }

    public Builder retransmitTimer(int retransmitTimer) {
      this.retransmitTimer = retransmitTimer;
      return this;
    }

    public Builder options(NeighborDiscoveryOptions options) {
      this.options = options;
      return this;
    }

    @Override
    public Packet build() {
      return new RouterAdvertisement(this);
    }

    @Override
    public Packet build(Memory buffer) {
      resetIndex(buffer);
      this.currentHopLimit = buffer.readByte();
      int bscratch = buffer.readByte();
      this.manageFlag = ((bscratch >> 7) & 0x1) == 1;
      this.otherFlag = ((bscratch >> 6) & 0x1) == 1;
      this.routerLifetime = buffer.readShort();
      this.reachableTime = buffer.readInt();
      this.retransmitTimer = buffer.readInt();
      this.options =
          (NeighborDiscoveryOptions) new NeighborDiscoveryOptions.Builder().build(buffer);
      this.buffer = buffer;
      this.payloadBuffer = buffer.slice();
      return new RouterAdvertisement(this);
    }
  }
}
