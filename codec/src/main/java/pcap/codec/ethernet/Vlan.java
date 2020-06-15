/** This code is licenced under the GPL version 2. */
package pcap.codec.ethernet;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import pcap.codec.AbstractPacket;
import pcap.codec.NetworkLayer;
import pcap.codec.Packet;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;
import pcap.common.util.NamedNumber;
import pcap.common.util.Strings;
import pcap.common.util.Validate;

/**
 * @see <a href="https://en.wikipedia.org/wiki/IEEE_802.1Q>Wikipedia</a>
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
@Inclubating
public class Vlan extends AbstractPacket {

  private final Header header;
  private final Packet payload;
  private final Builder builder;

  private Vlan(final Builder builder) {
    this.header = new Header(builder);
    this.payloadBuffer = builder.payloadBuffer;
    if (this.payloadBuffer != null
        && this.payloadBuffer.readerIndex() < this.payloadBuffer.writerIndex()) {
      this.payload =
          NetworkLayer.valueOf(this.header.type().value()).newInstance(this.payloadBuffer);
    } else {
      this.payload = null;
    }
    this.builder = builder;
  }

  public static Vlan newPacket(final Memory buffer) {
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
      this.buffer = resetIndex(builder.buffer, length());
      this.builder = builder;
    }

    public PriorityCodePoint priorityCodePoint() {
      return priorityCodePoint;
    }

    public int canonicalFormatIndicator() {
      return canonicalFormatIndicator & 0x01;
    }

    public int vlanIdentifier() {
      return vlanIdentifier & 0x0FFF;
    }

    public NetworkLayer type() {
      return type;
    }

    @Override
    public NetworkLayer payloadType() {
      return type;
    }

    @Override
    public int length() {
      return Header.VLAN_HEADER_LENGTH;
    }

    @Override
    public Memory buffer() {
      if (buffer == null) {
        buffer = ALLOCATOR.allocate(length());
        buffer.writeShort(
            ((priorityCodePoint.value() << 13) & 0x07)
                | ((canonicalFormatIndicator << 14) & 0x01)
                | (vlanIdentifier & 0x0FFF));
        buffer.writeShort(type.value());
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
      return canonicalFormatIndicator == header.canonicalFormatIndicator
          && vlanIdentifier == header.vlanIdentifier
          && priorityCodePoint.equals(header.priorityCodePoint)
          && type.equals(header.type);
    }

    @Override
    public int hashCode() {
      return Objects.hash(priorityCodePoint, canonicalFormatIndicator, vlanIdentifier, type);
    }

    @Override
    public String toString() {
      return Strings.toStringBuilder(this)
          .add("priorityCodePoint", priorityCodePoint())
          .add("canonicalFormatIndicator", canonicalFormatIndicator() & 0x01)
          .add("vlanIdentifier", vlanIdentifier() & 0x0FFF)
          .add("type", type())
          .toString();
    }
  }

  public static final class Builder extends AbstractPacket.Builder {

    private PriorityCodePoint priorityCodePoint = PriorityCodePoint.BE; // 3 bit
    private byte canonicalFormatIndicator; // 1 bit
    private short vlanIdentifier; // 12 bit
    private NetworkLayer type = NetworkLayer.DOT1Q_VLAN_TAGGED_FRAMES;

    private Memory buffer;
    private Memory payloadBuffer;

    /**
     * Priority code point (PCP).
     *
     * <p>A 3-bit field which refers to the IEEE 802.1p class of service and maps to the frame
     * priority level. Different PCP values can be used to prioritize different classes of traffic.
     */
    public Builder priorityCodePoint(final PriorityCodePoint priorityCodePoint) {
      this.priorityCodePoint = priorityCodePoint;
      return this;
    }

    /**
     * Drop eligible indicator (DEI).
     *
     * <p>A 1-bit field. (formerly CFI) May be used separately or in conjunction with PCP to
     * indicate frames eligible to be dropped in the presence of congestion.
     */
    public Builder canonicalFormatIndicator(final int canonicalFormatIndicator) {
      this.canonicalFormatIndicator = (byte) (canonicalFormatIndicator & 0x01);
      return this;
    }

    /**
     * VLAN identifier (VID).
     *
     * <p>A 12-bit field specifying the VLAN to which the frame belongs.
     */
    public Builder vlanIdentifier(final int vlanIdentifier) {
      this.vlanIdentifier = (short) (vlanIdentifier & 0x0FFF);
      return this;
    }

    /**
     * Next protocol type.
     *
     * <p>Example: {@link NetworkLayer#ARP}.
     */
    public Builder type(final NetworkLayer type) {
      this.type = type;
      return this;
    }

    @Override
    public Vlan build() {
      if (buffer != null) {
        return build(buffer);
      }
      return new Vlan(this);
    }

    @Override
    public Vlan build(final Memory buffer) {
      resetIndex(buffer);
      short tci = buffer.readShort();
      short type = buffer.readShort();
      this.priorityCodePoint = PriorityCodePoint.valueOf((byte) (tci >> 13 & 0x07));
      this.canonicalFormatIndicator = (byte) (tci >> 14 & 0x01);
      this.vlanIdentifier = (short) (tci & 0x0FFF);
      this.type = NetworkLayer.valueOf(type);
      this.buffer = buffer;
      this.payloadBuffer = buffer.slice();
      return new Vlan(this);
    }

    @Override
    public Builder reset() {
      return reset(readerIndex, Header.VLAN_HEADER_LENGTH);
    }

    @Override
    public Builder reset(int offset, int length) {
      if (buffer != null) {
        Validate.notIllegalArgument(offset + length <= buffer.capacity());
        Validate.notIllegalArgument(priorityCodePoint != null, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(canonicalFormatIndicator >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(vlanIdentifier >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(type != null, ILLEGAL_HEADER_EXCEPTION);
        int index = offset;
        int tci =
            ((priorityCodePoint.value() << 13) & 0x07)
                | ((canonicalFormatIndicator << 14) & 0x01)
                | (vlanIdentifier & 0x0FFF);
        buffer.setShort(index, tci);
        index += 2;
        buffer.setShort(index, type.value());
      }
      return this;
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

    private static final Map<Byte, PriorityCodePoint> REGISTRY = new HashMap<>();

    static {
      REGISTRY.put(BK.value(), BK);
      REGISTRY.put(BE.value(), BE);
      REGISTRY.put(EE.value(), EE);
      REGISTRY.put(CA.value(), CA);
      REGISTRY.put(VI.value(), VI);
      REGISTRY.put(VO.value(), VO);
      REGISTRY.put(IC.value(), IC);
      REGISTRY.put(NC.value(), NC);
    }

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
      REGISTRY.put(priorityCodePoint.value(), priorityCodePoint);
      return priorityCodePoint;
    }
  }
}
