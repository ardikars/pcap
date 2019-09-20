/** This code is licenced under the GPL version 2. */
package pcap.spi.exception.warn;

/**
 * This device doesn't support promiscuous mode ({@code 2}).
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public class PromiscuousModeNotSupported extends RuntimeException {

  public PromiscuousModeNotSupported(String message) {
    super(message);
  }
}
