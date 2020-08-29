/** This code is licenced under the GPL version 2. */
package pcap.common.util;

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
    int actualValueFromOffset = Integers.toInteger(bytes, 0);
    Assertions.assertEquals(intValue, actualValue);
    Assertions.assertEquals(intValue, actualValueFromOffset);
  }

  @Test
  public void toIntegerTestLE() {
    int intValue = 2147483647;
    byte[] bytes = Bytes.toByteArrayLE(intValue);
    int actualValue = Integers.toIntegerLE(bytes);
    int actualValueFromOffset = Integers.toIntegerLE(bytes, 0);
    Assertions.assertEquals(intValue, actualValue);
    Assertions.assertEquals(intValue, actualValueFromOffset);
  }
}
