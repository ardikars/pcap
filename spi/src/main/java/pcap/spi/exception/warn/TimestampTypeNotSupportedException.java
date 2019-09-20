/** This code is licenced under the GPL version 2. */
package pcap.spi.exception.warn;

/**
 * The requested time stamp type is not supported ({@code 3}).
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public class TimestampTypeNotSupportedException extends RuntimeException {

  public TimestampTypeNotSupportedException(String message) {
    super(message);
  }
}
