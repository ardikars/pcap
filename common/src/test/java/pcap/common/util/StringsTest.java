/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.common.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/** */
@RunWith(JUnitPlatform.class)
class StringsTest {

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
  void emptyTest() {
    Assertions.assertTrue(Strings.empty(null));
    Assertions.assertTrue(Strings.empty(""));
    Assertions.assertEquals("OK", Strings.empty(null, "OK"));
    Assertions.assertEquals("OK", Strings.empty("", "OK"));
    Assertions.assertEquals("YES", Strings.empty("YES", "OK"));
  }

  @Test
  void blankTest() {
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
  void lengthTest() {
    Assertions.assertEquals(6, Strings.length(4, 1, 5));
    Assertions.assertEquals(5, Strings.length(5, 0, 5));
    Assertions.assertEquals(1, Strings.length(1, 1, 1));
    Assertions.assertEquals(1, Strings.length(4, 0, 1));
  }

  @Test
  void byteToHexString() {
    Assertions.assertEquals("0a", Strings.hex(byteData[0]));
  }

  @Test
  void emptyByteArrayToHexString() {
    Assertions.assertEquals("", Strings.hex(new byte[0]));
    Assertions.assertEquals("", Strings.hex(byteData, 0, 0));
  }

  @Test
  void byteArrayToHexString() {
    Assertions.assertEquals("0a2b2d0205", Strings.hex(byteData));
  }

  @Test
  void byteArrayToHexStringWithRange() {
    Assertions.assertEquals("2b2d02", Strings.hex(byteData, 1, byteData.length - 2));
  }

  @Test
  void byteToPrettyHexString() {
    String expected =
        "         +-------------------------------------------------+\n"
            + "         |  0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f |\n"
            + "+--------+-------------------------------------------------+--------+\n"
            + "00000000 | 05 | .\n"
            + "+--------+-------------------------------------------------+--------+";
    Assertions.assertEquals(expected, Strings.prettyHex((byte) 5));
  }

  @Test
  void byteArrayToPrettyHexString() {
    final byte[] bytes = new byte[] {(byte) 10, (byte) 43, (byte) 45, (byte) 2, (byte) 0xff};
    String expected =
        "         +-------------------------------------------------+\n"
            + "         |  0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f |\n"
            + "+--------+-------------------------------------------------+--------+\n"
            + "00000000 | 0a 2b 2d 02 ff | .+-..\n"
            + "+--------+-------------------------------------------------+--------+";
    Assertions.assertEquals(expected, Strings.prettyHex(bytes));
  }

  @Test
  void byteArrayToPrettyHexStringWithRange() {
    final byte[] bytes = new byte[] {(byte) 10, (byte) 43, (byte) 45, (byte) 2, (byte) 0xff};
    String expected =
        "         +-------------------------------------------------+\n"
            + "         |  0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f |\n"
            + "+--------+-------------------------------------------------+--------+\n"
            + "00000000 | 0a 2b | .+\n"
            + "+--------+-------------------------------------------------+--------+";
    Assertions.assertEquals(expected, Strings.prettyHex(bytes, 0, bytes.length / 2));
  }

  @Test
  void toStringBuilderTest() {
    Assertions.assertNotNull(
        Strings.toStringJsonBuilder()
            .add("as", new byte[] {123})
            .add("as", new short[] {32763})
            .add("as", new int[] {2147483643})
            .add("as", new float[] {2147483643.2F})
            .add("as", new long[] {9223372036854775803L})
            .add("as", new double[] {9223372036854775803.6D})
            .add("as", new String[] {"d"})
            .toString());
    Assertions.assertNotNull(
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
