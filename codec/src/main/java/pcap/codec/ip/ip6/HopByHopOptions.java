/** This code is licenced under the GPL version 2. */
package pcap.codec.ip.ip6;

import pcap.codec.Packet;
import pcap.codec.TransportLayer;
import pcap.codec.ip.Ip6;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;
import pcap.common.util.Strings;
import pcap.common.util.Validate;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class HopByHopOptions extends Options {

  private final Header header;
  private final Packet payload;
  private final Builder builder;

  private HopByHopOptions(final Builder builder) {
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
        .add("payload", payload == null ? payload.getClass().getSimpleName() : "(None)")
        .toString();
  }

  public static final class Header extends Options.Header {

    private final Builder builder;

    protected Header(final Builder builder) {
      super(builder, builder.nextHeader);
      this.buffer = slice(builder.buffer, length());
      this.builder = builder;
    }

    @Override
    public String toString() {
      return super.toString();
    }

    @Override
    public Builder builder() {
      return builder;
    }
  }

  public static final class Builder extends Options.Builder {

    public Builder() {
      super(Ip6.IPV6_HOPOPT);
    }

    @Override
    public HopByHopOptions build() {
      return new HopByHopOptions(this);
    }

    @Override
    public HopByHopOptions build(final Memory buffer) {
      resetIndex(buffer);
      nextHeader = TransportLayer.valueOf(buffer.readByte());
      extensionLength = buffer.readByte();
      options =
          new byte
              [Options.Header.FIXED_OPTIONS_LENGTH + Options.Header.LENGTH_UNIT * extensionLength];
      buffer.readBytes(options);
      this.buffer = buffer;
      this.payloadBuffer = buffer.slice();
      return new HopByHopOptions(this);
    }

    @Override
    public Builder reset() {
      return reset(readerIndex, Header.FIXED_OPTIONS_LENGTH);
    }

    @Override
    public Builder reset(int offset, int length) {
      if (buffer != null) {
        Validate.notIllegalArgument(offset + length <= buffer.capacity());
        Validate.notIllegalArgument(nextHeader != null, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(extensionLength >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(options != null, ILLEGAL_HEADER_EXCEPTION);
        int index = offset;
        buffer.setByte(index, nextHeader.value());
        index += 1;
        buffer.setByte(index, extensionLength);
        index += 1;
        buffer.setBytes(index, options);
      }
      return this;
    }
  }
}
