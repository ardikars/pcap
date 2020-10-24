/** This code is licenced under the GPL version 2. */
package pcap.spi.exception;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@RunWith(JUnitPlatform.class)
public class TImeoutExceptionTest {

  @Test
  void throwExceptionTest() {
    Assertions.assertThrows(
        TimeoutException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            throw new TimeoutException("throwing exception.");
          }
        });
  }
}
