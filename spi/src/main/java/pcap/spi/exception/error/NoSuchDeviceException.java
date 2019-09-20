/** This code is licenced under the GPL version 2. */
package pcap.spi.exception.error;

/**
 * No such device exists ({@code -5}).
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public class NoSuchDeviceException extends Exception {

  public NoSuchDeviceException(String message) {
    super(message);
  }
}
