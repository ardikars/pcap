/** This code is licenced under the GPL version 2. */
package pcap.spi.exception.error;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/**
 * The operation can't be performed on already activated captures.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
@RunWith(JUnitPlatform.class)
public class ActivatedExceptionTest {

  @Test
  public void throwExceptionTest() {
    Assertions.assertThrows(
        ActivatedException.class,
        () -> {
          throw new ActivatedException("throwing exception.");
        });
  }
}
