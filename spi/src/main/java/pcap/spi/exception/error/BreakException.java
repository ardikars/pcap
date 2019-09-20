/** This code is licenced under the GPL version 2. */
package pcap.spi.exception.error;

/**
 * Loop terminated by pcap_breakloop ({@code -2}).
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public class BreakException extends Exception {

  public BreakException(String message) {
    super(message);
  }
}
