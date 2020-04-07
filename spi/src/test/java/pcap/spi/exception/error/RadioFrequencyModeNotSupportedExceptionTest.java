/** This code is licenced under the GPL version 2. */
package pcap.spi.exception.error;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/**
 * This device doesn't support rfmon (monitor) mode ({@code -6}).
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
@RunWith(JUnitPlatform.class)
public class RadioFrequencyModeNotSupportedExceptionTest {

  @Test
  public void throwExceptionTest() {
    Assertions.assertThrows(
        RadioFrequencyModeNotSupportedException.class,
        () -> {
          throw new RadioFrequencyModeNotSupportedException("throwing exception.");
        });
  }
}
