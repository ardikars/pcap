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
   * Returned direct buffer.
   *
   * @return returns direct buffer.
   * @since 1.0.0
   */
  ByteBuffer buffer();

  /**
   * Returns buffer capacity.
   *
   * @return Returns buffer capacity.
   * @since 1.0.0
   */
  long capacity();
}
