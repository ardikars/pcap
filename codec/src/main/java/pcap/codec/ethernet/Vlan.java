/** This code is licenced under the GPL version 2. */
package pcap.codec.ethernet;

import java.util.HashMap;
import java.util.Map;
import pcap.codec.AbstractPacket;
import pcap.codec.NetworkLayer;
import pcap.codec.Packet;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;
import pcap.common.util.NamedNumber;
import pcap.common.util.Validate;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class Vlan extends AbstractPacket {

  private final Header header;
  private final Packet payload;

  private Vlan(final Builder builder) {
    this.header = new Header(builder);
    this.payload =
        NetworkLayer.valueOf(this.header.getType().getValue()).newInstance(builder.payloadBuffer);
    payloadBuffer = builder.payloadBuffer;
  }

  public static Vlan newPacket(final Memory buffer) {
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

  public static final class Header extends AbstractPacket.Header {

    public static final int VLAN_HEADER_LENGTH = 4;

    private final PriorityCodePoint priorityCodePoint; // 3 bit
    private final byte canonicalFormatIndicator; // 1 bit
    private final short vlanIdentifier; // 12 bit
    private final NetworkLayer type;

    private final Builder builder;

    private Header(final Builder builder) {
      this.priorityCodePoint = builder.priorityCodePoint;
      this.canonicalFormatIndicator = builder.canonicalFormatIndicator;
      this.vlanIdentifier = builder.vlanIdentifier;
      this.type = builder.type;
      this.buffer = builder.buffer.slice(builder.buffer.readerIndex() - getLength(), getLength());
      this.builder = builder;
    }

    public PriorityCodePoint getPriorityCodePoint() {
      return priorityCodePoint;
    }

    public int getCanonicalFormatIndicator() {
      return canonicalFormatIndicator & 0x01;
    }

    public int getVlanIdentifier() {
      return vlanIdentifier & 0x0fff;
    }

    public NetworkLayer getType() {
      return type;
    }

    @Override
    public NetworkLayer getPayloadType() {
      return type;
    }

    @Override
    public int getLength() {
      return Header.VLAN_HEADER_LENGTH;
    }

    @Override
    public Memory getBuffer() {
      if (buffer == null) {
        buffer = ALLOCATOR.allocate(getLength());
        buffer.setShort(0, 0x8100); // IEEE 802.1Q VLAN-tagged frames
        buffer.setShort(
            2,
            ((priorityCodePoint.getValue() << 13) & 0x07)
                | ((canonicalFormatIndicator << 14) & 0x01)
                | (vlanIdentifier & 0x0fff));
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
          .append("\tpriorityCodePoint: ")
          .append(priorityCodePoint)
          .append('\n')
          .append("\tcanonicalFormatIndicator: ")
          .append(canonicalFormatIndicator)
          .append('\n')
          .append("\tvlanIdentifier: ")
          .append(vlanIdentifier)
          .append('\n')
          .append("\ttype: ")
          .append(type)
          .append('\n')
          .toString();
    }
  }

  @Override
  public String toString() {
    return new StringBuilder("[ Vlan Header (")
        .append(getHeader().getLength())
        .append(" bytes) ]")
        .append('\n')
        .append(header)
        .append("\tpayload: ")
        .append(payload != null ? payload.getClass().getSimpleName() : "")
        .toString();
  }

  public static final class Builder extends AbstractPacket.Builder {

    private PriorityCodePoint priorityCodePoint; // 3 bit
    private byte canonicalFormatIndicator; // 1 bit
    private short vlanIdentifier; // 12 bit
    private NetworkLayer type;

    private Memory buffer;
    private Memory payloadBuffer;

    public Builder priorityCodePoint(final PriorityCodePoint priorityCodePoint) {
      this.priorityCodePoint = priorityCodePoint;
      return this;
    }

    public Builder canonicalFormatIndicator(final int canonicalFormatIndicator) {
      this.canonicalFormatIndicator = (byte) (canonicalFormatIndicator & 0x01);
      return this;
    }

    public Builder vlanIdentifier(final int vlanIdentifier) {
      this.vlanIdentifier = (short) (vlanIdentifier & 0x0fff);
      return this;
    }

    public Builder type(final NetworkLayer type) {
      this.type = type;
      return this;
    }

    public Builder payloadBuffer(final Memory buffer) {
      this.payloadBuffer = buffer;
      return this;
    }

    @Override
    public Vlan build() {
      return new Vlan(this);
    }

    @Override
    public Vlan build(final Memory buffer) {
      short tci = buffer.readShort();
      short type = buffer.readShort();
      this.priorityCodePoint = PriorityCodePoint.valueOf((byte) (tci >> 13 & 0x07));
      this.canonicalFormatIndicator = (byte) (tci >> 14 & 0x01);
      this.vlanIdentifier = (short) (tci & 0x0fff);
      this.type = NetworkLayer.valueOf(type);
      this.buffer = buffer;
      this.payloadBuffer = buffer.slice();
      return new Vlan(this);
    }

    @Override
    public void reset() {
      if (buffer != null) {
        reset(buffer.readerIndex(), Header.VLAN_HEADER_LENGTH);
      }
    }

    @Override
    public void reset(int offset, int length) {
      if (buffer != null) {
        Validate.notIllegalArgument(offset + length <= buffer.capacity());
        Validate.notIllegalArgument(priorityCodePoint != null, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(canonicalFormatIndicator >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(vlanIdentifier >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(type != null, ILLEGAL_HEADER_EXCEPTION);
        int index = offset;
        int tci =
            ((priorityCodePoint.getValue() << 13) & 0x07)
                | ((canonicalFormatIndicator << 14) & 0x01)
                | (vlanIdentifier & 0x0fff);
        buffer.setShort(index, tci);
        index += 2;
        buffer.setShort(index, type.getValue());
      }
    }
  }

  /** @see <a href="https://en.wikipedia.org/wiki/IEEE_P802.1p">IEEE P802.1p</a> */
  public static final class PriorityCodePoint extends NamedNumber<Byte, PriorityCodePoint> {

    public static final PriorityCodePoint BK =
        new PriorityCodePoint((byte) 1, "Background (priority=0)");
    public static final PriorityCodePoint BE =
        new PriorityCodePoint((byte) 0, "Best effort (default)/(priority=1)");
    public static final PriorityCodePoint EE =
        new PriorityCodePoint((byte) 2, "Excellent effort (priority=2)");
    public static final PriorityCodePoint CA =
        new PriorityCodePoint((byte) 3, "Critical applications (priority=3)");
    public static final PriorityCodePoint VI =
        new PriorityCodePoint((byte) 4, "Video, < 100 ms latency and jitter (priority=4)");
    public static final PriorityCodePoint VO =
        new PriorityCodePoint((byte) 5, "Voice, < 10 ms latency and jitter (priority=5)");
    public static final PriorityCodePoint IC =
        new PriorityCodePoint((byte) 6, "Internetwork control (priority=6)");
    public static final PriorityCodePoint NC =
        new PriorityCodePoint((byte) 7, "Network control (priority=7)");

    private static final Map<Byte, PriorityCodePoint> REGISTRY =
        new HashMap<Byte, PriorityCodePoint>();

    protected PriorityCodePoint(Byte value, String name) {
      super(value, name);
    }

    /**
     * Get priority code point from value.
     *
     * @param value value.
     * @return returns {@link PriorityCodePoint}.
     */
    public static PriorityCodePoint valueOf(final byte value) {
      PriorityCodePoint priorityCodePoint = REGISTRY.get(value);
      if (priorityCodePoint == null) {
        return new PriorityCodePoint((byte) -1, "UNKONWN");
      }
      return priorityCodePoint;
    }

    /**
     * Add new {@link PriorityCodePoint} to registry.
     *
     * @param priorityCodePoint priority code point.
     * @return returns {@link PriorityCodePoint}.
     */
    public static PriorityCodePoint register(final PriorityCodePoint priorityCodePoint) {
      REGISTRY.put(priorityCodePoint.getValue(), priorityCodePoint);
      return priorityCodePoint;
    }

    static {
      REGISTRY.put(BK.getValue(), BK);
      REGISTRY.put(BE.getValue(), BE);
      REGISTRY.put(EE.getValue(), EE);
      REGISTRY.put(CA.getValue(), CA);
      REGISTRY.put(VI.getValue(), VI);
      REGISTRY.put(VO.getValue(), VO);
      REGISTRY.put(IC.getValue(), IC);
      REGISTRY.put(NC.getValue(), NC);
    }
  }
}
