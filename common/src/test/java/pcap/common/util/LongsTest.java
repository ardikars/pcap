/** This code is licenced under the GPL version 2. */
package pcap.common.util;

import java.nio.ByteOrder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@RunWith(JUnitPlatform.class)
public class LongsTest {

  @Test
  public void toIntegerTestBE() {
    long longValue = 9223372036854775807L;
    byte[] bytes = Bytes.toByteArray(longValue);
    long actualValue = Longs.toLong(bytes);
    Assertions.assertEquals(longValue, actualValue);
  }

  @Test
  public void toIntegerTestLE() {
    long longValue = 9223372036854775807L;
    byte[] bytes = Bytes.toByteArray(longValue, ByteOrder.LITTLE_ENDIAN);
    long actualValue = Longs.toLong(bytes, 0, ByteOrder.LITTLE_ENDIAN);
    Assertions.assertEquals(longValue, actualValue);
  }
}
