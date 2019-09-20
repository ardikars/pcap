/** This code is licenced under the GPL version 2. */
package pcap.spi.exception.error;

/**
 * No permission to open the device ({@code -8}).
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public class PermissionDeniedException extends Exception {

  public PermissionDeniedException(String message) {
    super(message);
  }
}
