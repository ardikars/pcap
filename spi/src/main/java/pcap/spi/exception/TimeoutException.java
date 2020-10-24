/** This code is licenced under the GPL version 2. */
package pcap.spi.exception;

/**
 * Timeout occurred while reading packet's.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
public class TimeoutException extends Exception {

  public TimeoutException(String message) {
    super(message);
  }
}
