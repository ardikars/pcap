/** This code is licenced under the GPL version 2. */
package pcap.common.util;

import java.nio.charset.Charset;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@RunWith(JUnitPlatform.class)
public class StringsTest extends BaseTest {

  private static final byte[] byteData =
      new byte[] {(byte) 10, (byte) 43, (byte) 45, (byte) 2, (byte) 5};
  private static final short[] shortData =
      new short[] {(short) 476, (short) 45832, (short) 455632, (short) 45522, (short) 45432};
  private static final int[] intData =
      new int[] {204743647, 2047483147, 2047883646, 2046483647, 2047483645};
  private static final float[] floatData =
      new float[] {204743647.1F, 2047483147.2F, 2047883646.3F, 2046483647.4F, 2047483645.5F};
  private static final long[] longData =
      new long[] {204543647L, 2047478347L, 2043424146L, 223543647L, 263453645L};
  private static final double[] doubleData =
      new double[] {204543647.1D, 2047478347.2D, 2043424146.3D, 223543647.4D, 263453645.5D};
  private static final String stringData = "Rock The Party!";

  @Test
  public void emptyTest() {
    Assertions.assertTrue(Strings.empty(null));
    Assertions.assertTrue(Strings.empty(""));
    Assertions.assertEquals("OK", Strings.empty(null, "OK"));
    Assertions.assertEquals("OK", Strings.empty("", "OK"));
    Assertions.assertEquals("YES", Strings.empty("YES", "OK"));
  }

  @Test
  public void blankTest() {
    Assertions.assertTrue(Strings.blank(" "));
    Assertions.assertTrue(Strings.blank(null));
    Assertions.assertTrue(Strings.blank("\t "));
    Assertions.assertTrue(Strings.blank("\r "));
    Assertions.assertTrue(Strings.blank("\n "));
    Assertions.assertTrue(Strings.blank("\0 "));
    Assertions.assertEquals("OK", Strings.blank(null, "OK"));
    Assertions.assertEquals("OK", Strings.blank("\t\r\n\0 ", "OK"));
    Assertions.assertEquals("YES", Strings.blank("YES", "OK"));
  }

  @Test
  public void lengthTest() {
    Assertions.assertEquals(6, Strings.length(4, 1, 5));
    Assertions.assertEquals(5, Strings.length(5, 0, 5));
    Assertions.assertEquals(1, Strings.length(1, 1, 1));
    Assertions.assertEquals(1, Strings.length(4, 0, 1));
  }

  @Test
  public void byteToHexString() {
    Assertions.assertEquals("0a", Strings.hex(byteData[0]));
  }

  @Test
  public void byteArrayToHexString() {
    Assertions.assertEquals("0a2b2d0205", Strings.hex(byteData));
  }

  @Test
  public void byteArrayToHexStringWithRange() {
    Assertions.assertEquals("2b2d02", Strings.hex(byteData, 1, byteData.length - 2));
  }

  @Test
  public void shortToHexString() {
    Assertions.assertEquals("01dc", Strings.hex(shortData[0]));
  }

  @Test
  public void shortArrayToHexString() {
    Assertions.assertEquals("01dcb308f3d0b1d2b178", Strings.hex(shortData));
  }

  @Test
  public void shortArrayToHexStringWithRange() {
    Assertions.assertEquals("b308f3d0b1d2", Strings.hex(shortData, 1, shortData.length - 2));
  }

  @Test
  public void intToHexString() {
    Assertions.assertEquals("0c3423df", Strings.hex(intData[0]));
  }

  @Test
  public void intArrayToHexString() {
    Assertions.assertEquals("0c3423df7a0a1d0b7a10397e79fadcbf7a0a1efd", Strings.hex(intData));
  }

  @Test
  public void intArrayToHexStringWithRange() {
    Assertions.assertEquals(
        "7a0a1d0b7a10397e79fadcbf", Strings.hex(intData, 1, intData.length - 2));
  }

  @Test
  public void floatToHexString() {
    Assertions.assertEquals("00x1.86847cp27", Strings.hex(floatData[0]));
  }

  @Test
  public void floatArrayToHexString() {
    Assertions.assertEquals(
        "00x1.86847cp2700x1.e82874p3000x1.e840e6p3000x1.e7eb72p3000x1.e8287cp30",
        Strings.hex(floatData));
  }

  @Test
  public void floatArrayToHexStringWithRange() {
    Assertions.assertEquals(
        "00x1.e82874p3000x1.e840e6p3000x1.e7eb72p30",
        Strings.hex(floatData, 1, floatData.length - 2));
  }

  @Test
  public void longToHexString() {
    Assertions.assertEquals("0c31169f", Strings.hex(longData[0]));
  }

  @Test
  public void longArrayToHexString() {
    Assertions.assertEquals("0c31169f7a0a0a4b79cc2d920d53015f0fb3fbcd", Strings.hex(longData));
  }

  @Test
  public void longArrayToHexStringWithRange() {
    Assertions.assertEquals(
        "7a0a0a4b79cc2d920d53015f0fb3fbcd", Strings.hex(longData, 1, longData.length - 1));
  }

  @Test
  public void doubleToHexString() {
    Assertions.assertEquals("0x1.8622d3e333333p27", Strings.hex(doubleData[0]));
  }

  @Test
  public void doubleArrayToHexString() {
    Assertions.assertEquals(
        "0x1.8622d3e333333p270x1.e828292cccccdp300x1.e730b64933333p300x1.aa602becccccdp270x1.f67f79bp27",
        Strings.hex(doubleData));
  }

  @Test
  public void doubleArrayToHexStringWithRange() {
    Assertions.assertEquals(
        "0x1.e828292cccccdp300x1.e730b64933333p300x1.aa602becccccdp270x1.f67f79bp27",
        Strings.hex(doubleData, 1, doubleData.length - 1));
  }

  @Test
  public void stringToHexString() {
    final String NULL = null;
    Assertions.assertEquals("526f636b2054686520506172747921", Strings.hex(stringData));
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Strings.hex("");
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Strings.hex(NULL);
          }
        });
    Assertions.assertEquals(
        "526f636b2054686520506172747921", Strings.hex(stringData, Charset.defaultCharset()));
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Strings.hex("", Charset.defaultCharset());
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Strings.hex(NULL, Charset.defaultCharset());
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Strings.hex(stringData, null);
          }
        });
  }

  @Test
  public void toStringBuilderTest() {
    Assertions.assertEquals(
        "{\"as\":\"7b\",\"as\":\"7ffb\",\"as\":\"7ffffffb\",\"as\":\"0x1.0p31\",\"as\":\"7ffffffffffffffb\",\"as\":\"0x1.0p63\",\"as\":\"[d]\"}",
        Strings.toStringJsonBuilder()
            .add("as", new byte[] {123})
            .add("as", new short[] {32763})
            .add("as", new int[] {2147483643})
            .add("as", new float[] {2147483643.2F})
            .add("as", new long[] {9223372036854775803L})
            .add("as", new double[] {9223372036854775803.6D})
            .add("as", new String[] {"d"})
            .toString());
    Assertions.assertEquals(
        "StringsTest{as=7b,as=7ffb,as=7ffffffb,as=0x1.0p31,as=7ffffffffffffffb,as=0x1.0p63,as=[d]}",
        Strings.toStringBuilder(this)
            .add("as", new byte[] {123})
            .add("as", new short[] {32763})
            .add("as", new int[] {2147483643})
            .add("as", new float[] {2147483643.2F})
            .add("as", new long[] {9223372036854775803L})
            .add("as", new double[] {9223372036854775803.6D})
            .add("as", new String[] {"d"})
            .toString());
    Assertions.assertEquals(
        "StringsTest{a=1}", Strings.toStringBuilder(this).add("a", 1).toString());
    Assertions.assertEquals(
        "{\"a\":\"d\"}", Strings.toStringJsonBuilder().add("a", "d").toString());
    Assertions.assertEquals("{\"a\":1}", Strings.toStringJsonBuilder().add("a", 1).toString());
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Strings.toStringBuilder(StringsTest.this).add(null, "").toString();
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Strings.toStringBuilder(StringsTest.this).add("", "").toString();
          }
        });
  }
}
