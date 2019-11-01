/** This code is licenced under the GPL version 2. */
package pcap.codec.ip.ip6;

import pcap.codec.Packet;
import pcap.codec.TransportLayer;
import pcap.codec.ip.Ip6;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;
import pcap.common.util.Validate;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class HopByHopOptions extends Options {

  private final Header header;
  private final Packet payload;

  private HopByHopOptions(final Builder builder) {
    this.header = new Header(builder);
    this.payloadBuffer = builder.payloadBuffer;
    if (this.payloadBuffer != null) {
      this.payload =
          TransportLayer.valueOf(header.payloadType().value()).newInstance(this.payloadBuffer);
    } else {
      this.payload = null;
    }
  }

  @Override
  public Header header() {
    return header;
  }

  @Override
  public Packet payload() {
    return payload;
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

  @Override
  public String toString() {
    return new StringBuilder("\t[ HopByHopOptions Header (")
        .append(header().length())
        .append(" bytes) ]")
        .append('\n')
        .append(header)
        .append("\t\tpayload: ")
        .append(payload != null ? payload.getClass().getSimpleName() : "")
        .toString();
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
    public void reset() {
      if (buffer != null) {
        reset(0, Header.FIXED_OPTIONS_LENGTH);
      }
    }

    @Override
    public void reset(int offset, int length) {
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
    }
  }
}
