/** This code is licenced under the GPL version 2. */
package pcap.spi.exception.error;

/**
 * The capture needs to be activated ({@code -3}).
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public class NotActivatedException extends Exception {

  public NotActivatedException(String message) {
    super(message);
  }
}
