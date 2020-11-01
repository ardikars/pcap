/** This code is licenced under the GPL version 2. */
package pcap.spi;

import pcap.spi.annotation.Incubating;

/**
 * Used by {@link PacketBuffer#cast(Class)}.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
@Incubating
public interface Packet {

  /**
   * Get packet buffer.
   *
   * @return returns packet buffer.
   * @since 1.0.0
   */
  @Incubating
  PacketBuffer buffer();

  /**
   * Abstract packet.
   *
   * @since 1.0.0
   */
  @Incubating
  abstract class Abstract implements Packet {

    protected final PacketBuffer buffer;
    protected final long offset;
    protected final long length;

    protected Abstract(PacketBuffer buffer) {
      this.buffer = buffer;
      if (buffer.readableBytes() < size()) {
        throw new IllegalArgumentException(
            String.format(
                "buffer.readableBytes: %d (expected: buffer.readableBytes(%d) >= packet.size(%d))",
                buffer.readableBytes(), buffer.readableBytes(), size()));
      }
      this.offset = buffer.readerIndex();
      this.length = size();
      buffer.readerIndex(offset + length);
    }

    /** {@inheritDoc} */
    @Override
    public PacketBuffer buffer() {
      return buffer;
    }

    /**
     * Get packet size.
     *
     * @return returns packet size.
     */
    protected abstract int size();
  }
}
