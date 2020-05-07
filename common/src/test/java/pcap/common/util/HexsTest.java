/** This code is licenced under the GPL version 2. */
package pcap.common.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@RunWith(JUnitPlatform.class)
public class HexsTest extends BaseTest {

  private static final byte[] byteData =
      new byte[] {(byte) 10, (byte) 43, (byte) 45, (byte) 2, (byte) 0xff};

  @Test
  public void parseHexToByteArray() {
    Assertions.assertArrayEquals(byteData, Hexs.parseHex("0a2b2d02ff"));
    Assertions.assertArrayEquals(byteData, Hexs.parseHex("0x0a2b2d02ff"));
    Assertions.assertThrows(IllegalArgumentException.class, () -> Hexs.parseHex("@"));
  }

  @Test
  public void hexDump() {
    String expected =
        "         +-------------------------------------------------+\n"
            + "         |  0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f |\n"
            + "+--------+-------------------------------------------------+--------+\n"
            + "00000000 | 0a 2b 2d 02 ff | .+-..\n"
            + "+--------+-------------------------------------------------+--------+";
    Assertions.assertEquals(expected, Hexs.toPrettyHexDump(byteData));
  }

  @Test
  public void bytestoHex() {
    Assertions.assertEquals("0a2b2d02ff", Hexs.toHexString(byteData));
  }

  @Test
  public void bytestoHexWithRange() {
    Assertions.assertEquals("2b2d02", Hexs.toHexString(byteData, 1, 3));
  }

  @Test
  public void emptyBytestoHex() {
    Assertions.assertEquals("", Hexs.toHexString(new byte[0]));
  }
}
