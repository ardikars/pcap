/** This code is licenced under the GPL version 2. */
package pcap.common.util;

import java.nio.ByteOrder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@RunWith(JUnitPlatform.class)
public class ShortsTest {

  @Test
  public void toShortTestBE() {
    short value = (short) 65533;
    byte[] bytes = Bytes.toByteArray(value);
    short actualValue = Shorts.toShort(bytes);
    Assertions.assertEquals(value, actualValue);
  }

  @Test
  public void toShortTestLE() {
    short shortValue = (short) 65533;
    byte[] bytes = Bytes.toByteArray(shortValue, ByteOrder.LITTLE_ENDIAN);
    short actualValue = Shorts.toShort(bytes, 0, ByteOrder.LITTLE_ENDIAN);
    Assertions.assertEquals(shortValue, actualValue);
  }
}
