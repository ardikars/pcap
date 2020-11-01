/** This code is licenced under the GPL version 2. */
package pcap.common.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@RunWith(JUnitPlatform.class)
public class LongsTest {

  @Test
  public void toLongTestBE() {
    long longValue = 9223372036854775807L;
    byte[] bytes = Bytes.toByteArray(longValue);
    long actualValue = Longs.toLong(bytes);
    long actualValueFromOffset = Longs.toLong(bytes, 0);
    Assertions.assertEquals(longValue, actualValue);
    Assertions.assertEquals(longValue, actualValueFromOffset);
  }

  @Test
  public void toLongTestLE() {
    long longValue = 9223372036854775807L;
    byte[] bytes = Bytes.toByteArrayLE(longValue);
    long actualValue = Longs.toLongLE(bytes);
    long actualValueFromOffset = Longs.toLongLE(bytes, 0);
    Assertions.assertEquals(longValue, actualValue);
    Assertions.assertEquals(longValue, actualValueFromOffset);
  }
}
