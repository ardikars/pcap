/** This code is licenced under the GPL version 2. */
package pcap.spi;

/**
 * A handle for writing packet to a capture file.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public interface Dumper {

  /**
   * Write a packet to a capture file.
   *
   * @param header packet header wrapper ({@link PacketHeader}).
   * @param buffer packet buffer wrapper ({@link PacketBuffer}).
   */
  void dump(PacketHeader header, PacketBuffer buffer);

  /**
   * Capture file position.
   *
   * @return returns capture file position.
   */
  long position();

  /** Flushes the output buffer to the capture file. */
  void flush();

  /** Closes a capture file. */
  void close();
}
