/** This code is licenced under the GPL version 2. */
package pcap.spi.exception.error;

/**
 * The requested time stamp precision is not supported ({@code -12}).
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
public class TimestampPrecisionNotSupportedException extends Exception {

  public TimestampPrecisionNotSupportedException(String message) {
    super(message);
  }
}
