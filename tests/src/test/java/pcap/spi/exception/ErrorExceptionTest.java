package pcap.spi.exception;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
public class ErrorExceptionTest {

  @Test
  public void throwExceptionTest() {
    Assertions.assertThrows(
        ErrorException.class,
        () -> {
          throw new ErrorException("throwing exception.");
        });
  }
}
