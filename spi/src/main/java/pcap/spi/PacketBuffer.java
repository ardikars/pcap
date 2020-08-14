/** This code is licenced under the GPL version 2. */
package pcap.spi;

import java.nio.ByteBuffer;

/**
 * A {@link ByteBuffer} wrapper.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
public interface PacketBuffer {

  /**
   * Returns buffer reader index.
   *
   * @return returns buffer reader index.
   */
  int readerIndex();

  /**
   * Set buffer reader index.
   *
   * @param readerIndex reader index.
   * @return returns this buffer.
   * @since 1.0.0
   */
  PacketBuffer readerIndex(int readerIndex);

  /**
   * Returns buffer writer index.
   *
   * @return returns buffer writer index.
   * @since 1.0.0
   */
  int writerIndex();

  /**
   * Set writer index.
   *
   * @param writerIndex writer index.
   * @return returns this buffer.
   * @since 1.0.0
   */
  PacketBuffer writerIndex(int writerIndex);

  /**
   * Returns buffer capacity.
   *
   * @return returns buffer capacity.
   * @since 1.0.0
   */
  int capacity();

  /**
   * Returns first byte address of this buffer.
   *
   * @return returns first byte address of this buffer.
   */
  long address();

  /** Release this buffer. */
  boolean release();
}
