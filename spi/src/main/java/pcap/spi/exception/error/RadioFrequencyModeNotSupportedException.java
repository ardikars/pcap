/** This code is licenced under the GPL version 2. */
package pcap.spi.exception.error;

/**
 * This device doesn't support rfmon (monitor) mode ({@code -6}).
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
public class RadioFrequencyModeNotSupportedException extends Exception {

  public RadioFrequencyModeNotSupportedException(String message) {
    super(message);
  }
}
