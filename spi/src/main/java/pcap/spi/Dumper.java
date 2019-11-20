/** This code is licenced under the GPL version 2. */
package pcap.spi;

/**
 * A handle for writing packet to a capture file.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
public interface Dumper extends AutoCloseable {

  /**
   * Write a packet to a capture file.
   *
   * @param header packet header wrapper ({@link PacketHeader}).
   * @param buffer packet buffer wrapper ({@link PacketBuffer}).
   * @since 1.0.0
   */
  void dump(PacketHeader header, PacketBuffer buffer);

  /**
   * Capture file position.
   *
   * @return returns capture file position.
   * @since 1.0.0
   */
  long position();

  /**
   * Flushes the output buffer to the capture file.
   *
   * @since 1.0.0
   */
  void flush();

  /**
   * Closes a capture file.
   *
   * @since 1.0.0
   */
  @Override
  void close();
}
