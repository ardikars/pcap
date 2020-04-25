/** This code is licenced under the GPL version 2. */
package pcap.codec;

import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;
import pcap.common.util.NamedNumber;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class UnknownPacket extends AbstractPacket {

  public static final NamedNumber<Integer, ?> UNKNOWN_PAYLOAD_TYPE =
      null; /*new NamedNumber<Integer, NamedNumber>(-1, "UNKNOWN PAYLOAD TYPE") {

            	@Override
            	public Integer getValue() {
            		return super.getValue();
            	}

            };*/

  private final Header header;
  private final Packet payload;
  private final Builder builder;

  private UnknownPacket(final Builder builder) {
    this.header = new Header(builder);
    this.payload = null;
    payloadBuffer = builder.payloadBuffer;
    this.builder = builder;
  }

  public static UnknownPacket newPacket(final Memory buffer) {
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

  public static final class Header extends AbstractPacket.Header {

    private final Memory buffer;

    private final Builder builder;

    public Header(final Builder builder) {
      this.buffer = builder.payloadBuffer;
      this.builder = builder;
    }

    @Override
    public int length() {
      return buffer.capacity();
    }

    @Override
    public Memory buffer() {
      return buffer;
    }

    @SuppressWarnings("TypeParameterUnusedInFormals")
    @Override
    public <T extends NamedNumber> T payloadType() {
      return (T) UNKNOWN_PAYLOAD_TYPE;
    }

    @Override
    public Builder builder() {
      return builder;
    }

    @Override
    public String toString() {
      return new StringBuilder().append("\tbuffer: ").append(buffer).append('\n').toString();
    }
  }

  @Override
  public String toString() {
    return new StringBuilder("[ UnknownPacket Header (")
        .append(header().length())
        .append(" bytes) ]")
        .append('\n')
        .append(header)
        .toString();
  }

  public static final class Builder extends AbstractPacket.Builder {

    private Memory payloadBuffer;

    public Builder payloadBuffer(final Memory buffer) {
      this.payloadBuffer = buffer;
      return this;
    }

    @Override
    public UnknownPacket build() {
      return new UnknownPacket(this);
    }

    @Override
    public UnknownPacket build(Memory buffer) {
      Builder builder = new Builder().payloadBuffer(buffer);
      return new UnknownPacket(builder);
    }

    @Override
    public void reset() {
      // nothing to do
    }

    @Override
    public void reset(int offset, int length) {
      // do nothing
    }
  }
}
