/** This code is licenced under the GPL version 2. */
package pcap.spi.exception.error;

/**
 * The operation can't be performed on already activated captures.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public class ActivatedException extends Exception {

  public ActivatedException(String message) {
    super(message);
  }
}
