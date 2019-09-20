/** This code is licenced under the GPL version 2. */
package pcap.spi.exception.error;

/**
 * You don't have permission to capture in promiscuous mode ({@code -11}).
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public class PromiscuousModePermissionDeniedException extends Exception {

  public PromiscuousModePermissionDeniedException(String message) {
    super(message);
  }
}
