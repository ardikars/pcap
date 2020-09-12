/** This code is licenced under the GPL version 2. */
package pcap.spi.exception.error;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/**
 * Loop terminated by pcap_breakloop ({@code -2}).
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
@RunWith(JUnitPlatform.class)
public class BreakExceptionTest {

  @Test
  public void throwExceptionTest() {
    Assertions.assertThrows(
        BreakException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            throw new BreakException("throwing exception.");
          }
        });
  }
}
