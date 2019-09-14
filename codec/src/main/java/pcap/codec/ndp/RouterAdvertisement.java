/** This code is licenced under the GPL version 2. */
package pcap.codec.ndp;

import pcap.codec.AbstractPacket;
import pcap.codec.Packet;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;
import pcap.common.util.NamedNumber;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class RouterAdvertisement extends AbstractPacket {

  private final Header header;
  private final Packet payload;

  /**
   * Builder Router Advertisement packet.
   *
   * @param builder builder.
   */
  public RouterAdvertisement(Builder builder) {
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
      this.buffer = builder.buffer.slice(builder.buffer.readerIndex() - getLength(), getLength());
      this.builder = builder;
    }

    public int getCurrentHopLimit() {
      return currentHopLimit & 0xff;
    }

    public boolean isManageFlag() {
      return manageFlag;
    }

    public boolean isOtherFlag() {
      return otherFlag;
    }

    public int getRouterLifetime() {
      return routerLifetime & 0xffff;
    }

    public int getReachableTime() {
      return reachableTime;
    }

    public int getRetransmitTimer() {
      return retransmitTimer;
    }

    public NeighborDiscoveryOptions getOptions() {
      return options;
    }

    @Override
    public <T extends NamedNumber> T getPayloadType() {
      return null;
    }

    @Override
    public int getLength() {
      return ROUTER_ADVERTISEMENT_HEADER_LENGTH + options.getHeader().getLength();
    }

    @Override
    public Memory getBuffer() {
      if (buffer == null) {
        buffer = ALLOCATOR.allocate(getLength());
        buffer.writeByte(currentHopLimit);
        buffer.writeByte((manageFlag ? 1 : 0) << 7 | (otherFlag ? 1 : 0) << 6);
        buffer.writeShort(routerLifetime);
        buffer.writeInt(reachableTime);
        buffer.writeInt(retransmitTimer);
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
          .append("\tcurrentHopLimit: ")
          .append(currentHopLimit)
          .append('\n')
          .append("\tmanageFlag: ")
          .append(manageFlag)
          .append('\n')
          .append("\totherFlag: ")
          .append(otherFlag)
          .append('\n')
          .append("\trouterLifetime: ")
          .append(routerLifetime)
          .append('\n')
          .append("\treachableTime: ")
          .append(reachableTime)
          .append('\n')
          .append("\tretransmitTimer: ")
          .append(retransmitTimer)
          .append('\n')
          .append("\toptions: ")
          .append(options)
          .append('\n')
          .toString();
    }
  }

  @Override
  public String toString() {
    return new StringBuilder("[ RouterAdvertisement Header (")
        .append(getHeader().getLength())
        .append(" bytes) ]")
        .append('\n')
        .append(header)
        .append("\tpayload: ")
        .append(payload != null ? payload.getClass().getSimpleName() : "")
        .toString();
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
      this.currentHopLimit = buffer.readByte();
      int bscratch = buffer.readByte();
      this.manageFlag = ((bscratch >> 7) & 0x1) == 1 ? true : false;
      this.otherFlag = ((bscratch >> 6) & 0x1) == 1 ? true : false;
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
