/** This code is licenced under the GPL version 2. */
package pcap.spi.exception;

/**
 * Generic error code ({@code -1}).
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
public class ErrorException extends Exception {

  public ErrorException(String message) {
    super(message);
  }
}
