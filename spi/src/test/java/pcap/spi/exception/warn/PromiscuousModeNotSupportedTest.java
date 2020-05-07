/** This code is licenced under the GPL version 2. */
package pcap.spi.exception.warn;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@RunWith(JUnitPlatform.class)
public class PromiscuousModeNotSupportedTest {

  @Test
  public void throwExceptionTest() {
    Assertions.assertThrows(
        PromiscuousModeNotSupported.class,
        () -> {
          throw new PromiscuousModeNotSupported("throwing exception.");
        });
  }
}
