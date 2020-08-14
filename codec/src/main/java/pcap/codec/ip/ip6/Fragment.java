/** This code is licenced under the GPL version 2. */
package pcap.codec.ip.ip6;

import java.util.Objects;
import pcap.codec.AbstractPacket;
import pcap.codec.Packet;
import pcap.codec.TransportLayer;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;
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
    if (this.payloadBuffer != null
        && this.payloadBuffer.readerIndex() < this.payloadBuffer.writerIndex()) {
      this.payload =
          TransportLayer.valueOf(header.payloadType().value()).newInstance(this.payloadBuffer);
    } else {
      this.payload = null;
    }
    this.builder = builder;
  }

  public static Fragment newPacket(final Memory buffer) {
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
        .add("header", header)
        .add("payload", payload != null ? payload.getClass().getSimpleName() : "(None)")
        .toString();
  }

  public static final class Header extends AbstractPacket.Header {

    public static final int FIXED_FRAGMENT_HEADER_LENGTH = 8;

    private final TransportLayer nextHeader;
    private final short fragmentOffset;
    private final boolean moreFlag;
    private final int identification;

    private final Builder builder;

    private Header(final Builder builder) {
      this.nextHeader = builder.nextHeader;
      this.fragmentOffset = builder.fragmentOffset;
      this.moreFlag = builder.moreFlag;
      this.identification = builder.identification;
      this.buffer = resetIndex(builder.buffer, length());
      this.builder = builder;
    }

    /**
     * Next protocol type.
     *
     * @return returns {@link TransportLayer}.
     */
    public TransportLayer nextHeader() {
      return nextHeader;
    }

    /**
     * Fragment offset.
     *
     * @return returns fragment offset.
     */
    public int fragmentOffset() {
      return fragmentOffset & 0x1fff;
    }

    /**
     * Flag type.
     *
     * @return returns {@code true} for more flag, {@code false} otherwise.
     */
    public boolean moreFlag() {
      return moreFlag;
    }

    /**
     * Identification.
     *
     * @return returns identification.
     */
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
        buffer.writeShort((fragmentOffset & 0x1fff) << 3 | (moreFlag ? 1 : 0));
        buffer.writeInt(identification);
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
      return fragmentOffset == header.fragmentOffset()
          && identification == header.identification()
          && nextHeader.equals(header.nextHeader())
          && moreFlag == header.moreFlag();
    }

    @Override
    public int hashCode() {
      return Objects.hash(nextHeader, fragmentOffset, moreFlag, identification);
    }

    @Override
    public String toString() {
      return Strings.toStringBuilder(this)
          .add("nextHeader", nextHeader)
          .add("fragmentOffset", fragmentOffset)
          .add("moreFlag", moreFlag)
          .add("identification", identification)
          .toString();
    }
  }

  public static final class Builder extends AbstractPacket.Builder {

    private TransportLayer nextHeader;
    private short fragmentOffset;
    private boolean moreFlag;
    private int identification;

    private Memory buffer;
    private Memory payloadBuffer;

    /**
     * Next protocol type.
     *
     * @param nextHeader next protocol type.
     * @return returns this {@link Builder}.
     */
    public Builder nextHeader(TransportLayer nextHeader) {
      this.nextHeader = nextHeader;
      return this;
    }

    /**
     * Fragment offset.
     *
     * @param fragmentOffset fragment offset.
     * @return returns this {@link Builder}.
     */
    public Builder fragmentOffset(int fragmentOffset) {
      this.fragmentOffset = (short) (fragmentOffset & 0x1fff);
      return this;
    }

    /**
     * Flag type.
     *
     * @param moreFlag flag type.
     * @return returns this {@link Builder}.
     */
    public Builder moreFlag(boolean moreFlag) {
      this.moreFlag = moreFlag;
      return this;
    }

    /**
     * Identification.
     *
     * @param identification identification.
     * @return returns this {@link Builder}.
     */
    public Builder identification(int identification) {
      this.identification = identification;
      return this;
    }

    @Override
    public Builder payload(AbstractPacket packet) {
      this.payloadBuffer = packet.payloadBuffer();
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
      this.moreFlag = (sscratch & 0x1) == 1 ? true : false;
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
        resetIndex(buffer);
        Validate.notIllegalArgument(offset + length <= buffer.capacity());
        Validate.notIllegalArgument(nextHeader != null, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(fragmentOffset >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(identification >= 0, ILLEGAL_HEADER_EXCEPTION);
        int index = offset;
        buffer.setByte(index, nextHeader.value());
        index += 1;
        buffer.setByte(index, 0); // reserved
        index += 1;
        int sscratch = (fragmentOffset & 0x1fff) << 3 | (moreFlag ? 1 : 0);
        buffer.setShort(index, sscratch);
        index += 2;
        buffer.setInt(index, identification);
      }
      return this;
    }
  }
}
