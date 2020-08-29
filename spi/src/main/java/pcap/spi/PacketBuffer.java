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
  long readerIndex();

  /**
   * Set buffer reader index.
   *
   * @param readerIndex reader index.
   * @return returns this buffer.
   * @since 1.0.0
   */
  PacketBuffer readerIndex(long readerIndex);

  /**
   * Returns buffer writer index.
   *
   * @return returns buffer writer index.
   * @since 1.0.0
   */
  long writerIndex();

  /**
   * Set writer index.
   *
   * @param writerIndex writer index.
   * @return returns this buffer.
   * @since 1.0.0
   */
  PacketBuffer writerIndex(long writerIndex);

  /**
   * Returns buffer capacity.
   *
   * @return returns buffer capacity.
   * @since 1.0.0
   */
  long capacity();

  /**
   * Returns first byte address of this buffer.
   *
   * @return returns first byte address of this buffer.
   * @since 1.0.0
   */
  long address();

  /**
   * Release this buffer.
   *
   * @return returns {@code true} if buffer's released successfully, {@code false} otherwise.
   * @since 1.0.0
   */
  boolean release();
}
