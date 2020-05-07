/** This code is licenced under the GPL version 2. */
package pcap.codec.ip.ip6;

import java.util.HashMap;
import java.util.Map;
import pcap.codec.AbstractPacket;
import pcap.codec.Packet;
import pcap.codec.TransportLayer;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;
import pcap.common.util.NamedNumber;
import pcap.common.util.Strings;
import pcap.common.util.Validate;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class Fragment extends AbstractPacket {

  private final Header header;
  private final Packet payload;
  private final Builder builder;

  private Fragment(final Builder builder) {
    this.header = new Header(builder);
    this.payloadBuffer = builder.payloadBuffer;
    if (this.payloadBuffer != null) {
      this.payload =
          TransportLayer.valueOf(header.payloadType().value()).newInstance(this.payloadBuffer);
    } else {
      this.payload = null;
    }
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

    public static final int FIXED_FRAGMENT_HEADER_LENGTH = 8;

    private final TransportLayer nextHeader;
    private final short fragmentOffset;
    private final FlagType flagType;
    private final int identification;

    private final Builder builder;

    private Header(final Builder builder) {
      this.nextHeader = builder.nextHeader;
      this.fragmentOffset = builder.fragmentOffset;
      this.flagType = builder.flagType;
      this.identification = builder.identification;
      this.buffer = slice(builder.buffer, length());
      this.builder = builder;
    }

    public TransportLayer nextHeader() {
      return nextHeader;
    }

    public int fragmentOffset() {
      return fragmentOffset & 0x1fff;
    }

    public FlagType flagType() {
      return flagType;
    }

    public int identification() {
      return identification;
    }

    @Override
    public TransportLayer payloadType() {
      return nextHeader;
    }

    @Override
    public int length() {
      return FIXED_FRAGMENT_HEADER_LENGTH;
    }

    @Override
    public Memory buffer() {
      if (buffer == null) {
        buffer = ALLOCATOR.allocate(length());
        buffer.writeByte(nextHeader.value());
        buffer.writeByte(0); // reserved
        buffer.writeShort((fragmentOffset & 0x1fff) << 3 | flagType.value() & 0x1);
        buffer.writeInt(identification);
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
          .add("nextHeader", nextHeader)
          .add("fragmentOffset", fragmentOffset)
          .add("flagType", flagType)
          .add("identification", identification)
          .toString();
    }
  }

  public static final class Builder extends AbstractPacket.Builder {

    private TransportLayer nextHeader;
    private short fragmentOffset;
    private FlagType flagType;
    private int identification;

    private Memory buffer;
    private Memory payloadBuffer;

    public Builder nextHeader(TransportLayer nextHeader) {
      this.nextHeader = nextHeader;
      return this;
    }

    public Builder fragmentOffset(int fragmentOffset) {
      this.fragmentOffset = (short) (fragmentOffset & 0x1fff);
      return this;
    }

    public Builder flagType(FlagType flagType) {
      this.flagType = flagType;
      return this;
    }

    public Builder identification(int identification) {
      this.identification = identification;
      return this;
    }

    @Override
    public Fragment build() {
      return new Fragment(this);
    }

    @Override
    public Fragment build(final Memory buffer) {
      resetIndex(buffer);
      this.nextHeader = TransportLayer.valueOf(buffer.readByte());
      buffer.readByte(); // reserved
      short sscratch = buffer.readShort();
      this.fragmentOffset = (short) (sscratch >> 3 & 0x1fff);
      this.flagType = FlagType.valueOf((byte) (sscratch & 0x1));
      this.identification = buffer.readInt();
      this.buffer = buffer;
      this.payloadBuffer = buffer.slice();
      return new Fragment(this);
    }

    @Override
    public Builder reset() {
      return reset(readerIndex, Header.FIXED_FRAGMENT_HEADER_LENGTH);
    }

    @Override
    public Builder reset(int offset, int length) {
      if (buffer != null) {
        Validate.notIllegalArgument(offset + length <= buffer.capacity());
        Validate.notIllegalArgument(nextHeader != null, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(fragmentOffset >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(flagType != null, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(identification >= 0, ILLEGAL_HEADER_EXCEPTION);
        int index = offset;
        buffer.setByte(index, nextHeader.value());
        index += 1;
        buffer.setByte(index, 0); // reserved
        index += 1;
        int sscratch = (fragmentOffset & 0x1fff) << 3 | flagType.value() & 0x1;
        buffer.setShort(index, sscratch);
        index += 2;
        buffer.setIndex(index, identification);
      }
      return this;
    }
  }

  public static final class FlagType extends NamedNumber<Byte, FlagType> {

    public static final FlagType LAST_FRAGMENT = new FlagType((byte) 0, "Last fragment.");

    public static final FlagType MORE_FRAGMENT = new FlagType((byte) 1, "More fragment.");

    public static final FlagType UNKNOWN = new FlagType((byte) -1, "UNKNOWN.");

    private static final Map<Byte, FlagType> REGISTRY = new HashMap<>();

    protected FlagType(Byte value, String name) {
      super(value, name);
    }

    public static FlagType register(final FlagType flagType) {
      REGISTRY.put(flagType.value(), flagType);
      return flagType;
    }

    /**
     * Get flag type from value.
     *
     * @param flag value.
     * @return returns {@link FlagType}.
     */
    public static FlagType valueOf(final byte flag) {
      FlagType flagType = REGISTRY.get(flag);
      if (flagType == null) {
        return UNKNOWN;
      }
      return flagType;
    }
  }
}
