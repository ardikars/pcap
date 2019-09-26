/** This code is licenced under the GPL version 2. */
package pcap.codec.udp;

import pcap.codec.AbstractPacket;
import pcap.codec.ApplicationLayer;
import pcap.codec.Packet;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;
import pcap.common.util.Validate;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class Udp extends AbstractPacket {

  private final Header header;
  private final Packet payload;

  private Udp(final Builder builder) {
    this.header = new Header(builder);
    this.payload =
        ApplicationLayer.valueOf(this.header.getPayloadType().getValue())
            .newInstance(builder.payloadBuffer);
    payloadBuffer = builder.payloadBuffer;
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

    public static final int UDP_HEADER_LENGTH = 8;

    private final short sourcePort;
    private final short destinationPort;
    private final short length;
    private final short checksum;

    private final Builder builder;

    private Header(final Builder builder) {
      this.sourcePort = builder.sourcePort;
      this.destinationPort = builder.destinationPort;
      this.length = builder.length;
      this.checksum = builder.checksum;
      this.buffer = slice(builder.buffer, getLength());
      this.builder = builder;
    }

    public int getSourcePort() {
      return sourcePort & 0xffff;
    }

    public int getDestinationPort() {
      return destinationPort & 0xffff;
    }

    public int getChecksum() {
      return checksum & 0xffff;
    }

    @Override
    public ApplicationLayer getPayloadType() {
      return ApplicationLayer.valueOf(destinationPort);
    }

    @Override
    public int getLength() {
      return UDP_HEADER_LENGTH;
    }

    @Override
    public Memory getBuffer() {
      if (buffer == null) {
        buffer = ALLOCATOR.allocate(getLength());
        buffer.writeShort(this.sourcePort);
        buffer.writeShort(this.destinationPort);
        buffer.writeShort(this.length);
        buffer.writeShort(this.checksum);
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
          .append("\tsourcePort: ")
          .append(sourcePort)
          .append('\n')
          .append("\tdestinationPort: ")
          .append(destinationPort)
          .append('\n')
          .append("\tlength: ")
          .append(length)
          .append('\n')
          .append("\tchecksum: ")
          .append(checksum)
          .append('\n')
          .toString();
    }
  }

  @Override
  public String toString() {
    return new StringBuilder("[ Udp Header (")
        .append(getHeader().getLength())
        .append(" bytes) ]")
        .append('\n')
        .append(header)
        .append("\tpayload: ")
        .append(payload != null ? payload.getClass().getSimpleName() : "")
        .toString();
  }

  public static class Builder extends AbstractPacket.Builder {

    private short sourcePort;
    private short destinationPort;
    private short length;
    private short checksum;

    private Memory buffer;
    private Memory payloadBuffer;

    public Builder sourcePort(int sourcePort) {
      this.sourcePort = (short) (sourcePort & 0xffff);
      return this;
    }

    public Builder destinationPort(int destinationPort) {
      this.destinationPort = (short) (destinationPort & 0xffff);
      return this;
    }

    public Builder length(int length) {
      this.length = (short) (length & 0xffff);
      return this;
    }

    public Builder checksum(int checksum) {
      this.checksum = (short) (checksum & 0xffff);
      return this;
    }

    public Builder payloadBuffer(Memory payloadBuffer) {
      this.payloadBuffer = payloadBuffer;
      return this;
    }

    @Override
    public Packet build() {
      return new Udp(this);
    }

    @Override
    public Packet build(Memory buffer) {
      this.sourcePort = buffer.readShort();
      this.destinationPort = buffer.readShort();
      this.length = buffer.readShort();
      this.checksum = buffer.readShort();
      this.buffer = buffer;
      this.payloadBuffer = buffer.slice();
      return new Udp(this);
    }

    @Override
    public void reset() {
      if (buffer != null) {
        reset(0, Header.UDP_HEADER_LENGTH);
      }
    }

    @Override
    public void reset(int offset, int length) {
      if (buffer != null) {
        Validate.notIllegalArgument(offset + length <= buffer.capacity());
        Validate.notIllegalArgument(sourcePort >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(destinationPort >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(this.length >= 0, ILLEGAL_HEADER_EXCEPTION);
        Validate.notIllegalArgument(checksum >= 0, ILLEGAL_HEADER_EXCEPTION);
        int index = offset;
        buffer.setShort(index, sourcePort);
        index += 2;
        buffer.setShort(index, destinationPort);
        index += 2;
        buffer.setShort(index, this.length);
        index += 2;
        buffer.setShort(index, checksum);
      }
    }
  }
}
