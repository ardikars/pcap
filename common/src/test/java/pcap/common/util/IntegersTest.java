/** This code is licenced under the GPL version 2. */
package pcap.common.util;

import java.nio.ByteOrder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@RunWith(JUnitPlatform.class)
public class IntegersTest {

  @Test
  public void toIntegerTestBE() {
    int intValue = 2147483647;
    byte[] bytes = Bytes.toByteArray(intValue);
    int actualValue = Integers.toInteger(bytes);
    Assertions.assertEquals(intValue, actualValue);
  }

  @Test
  public void toIntegerTestLE() {
    int intValue = 2147483647;
    byte[] bytes = Bytes.toByteArray(intValue, ByteOrder.LITTLE_ENDIAN);
    int actualValue = Integers.toInteger(bytes, 0, ByteOrder.LITTLE_ENDIAN);
    Assertions.assertEquals(intValue, actualValue);
  }
}
