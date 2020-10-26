/** This code is licenced under the GPL version 2. */
package pcap.spi.exception;

import pcap.spi.annotation.Incubating;

/**
 * Memory leak detected.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
@Incubating
public class MemoryLeakException extends RuntimeException {

  public MemoryLeakException(String message) {
    super(message);
  }
}
