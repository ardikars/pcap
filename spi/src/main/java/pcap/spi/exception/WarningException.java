/** This code is licenced under the GPL version 2. */
package pcap.spi.exception;

/**
 * Generic warning code ({@code 1}).
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
public class WarningException extends RuntimeException {

  public WarningException(String message) {
    super(message);
  }
}
