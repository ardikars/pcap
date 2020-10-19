package pcap.spi;

import pcap.spi.annotation.Incubating;

@Incubating
public interface Packet {

  @Incubating
  PacketBuffer buffer();

  @Incubating
  abstract class Abstract implements Packet {

    protected final PacketBuffer buffer;
    protected final long offset;
    protected final long length;

    public Abstract(PacketBuffer buffer) {
      if (buffer.readableBytes() < size()) {
        throw new IllegalArgumentException(
            String.format(
                "buffer.readableBytes: %d (expected: buffer.readableBytes(%d) >= packet.size(%d))",
                buffer.readableBytes(), buffer.readableBytes(), size()));
      }
      this.buffer = buffer;
      this.offset = buffer.readerIndex();
      this.length = size();
      buffer.readerIndex(offset + length);
    }

    protected abstract int size();
  }
}
