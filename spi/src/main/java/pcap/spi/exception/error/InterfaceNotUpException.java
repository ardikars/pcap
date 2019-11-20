/** This code is licenced under the GPL version 2. */
package pcap.spi.exception.error;

/**
 * Interface isn't up ({@code -9}).
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
public class InterfaceNotUpException extends Exception {

  public InterfaceNotUpException(String message) {
    super(message);
  }
}
