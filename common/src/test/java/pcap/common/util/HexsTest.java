/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.common.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

/** */
class HexsTest {

  private static final byte[] byteData =
      new byte[] {(byte) 10, (byte) 43, (byte) 45, (byte) 2, (byte) 0xff};

  @Test
  void parseHexToByteArray() {
    Assertions.assertArrayEquals(byteData, Hexs.parseHex("0a2b2d02ff"));
    Assertions.assertArrayEquals(byteData, Hexs.parseHex("0x0a2b2d02ff"));
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Hexs.parseHex("@");
          }
        });
  }

  @Test
  void decodeHexNibble() {
    Assertions.assertEquals(0, Hexs.decodeHexNibble('0'));
    Assertions.assertNotEquals(1, Hexs.decodeHexNibble('0'));
  }

  @Test
  void parseHex() {
    for (int i = 0; i < 256; i++) {
      String hex = Integer.toString(i, 16);
      if (hex.length() == 1) {
        hex = "0" + hex;
      }
      Assertions.assertEquals(i, Hexs.parseHex(hex)[0] & 0xFF);
      Assertions.assertEquals(i, Hexs.parseHex("0x" + hex)[0] & 0xFF);
    }
    Assertions.assertArrayEquals(new byte[0], Hexs.parseHex("0x"));
    Assertions.assertArrayEquals(new byte[0], Hexs.parseHex(""));
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Hexs.parseHex("0x0");
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Hexs.parseHex("0y00");
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Hexs.parseHex("xx00");
          }
        });
  }
}
