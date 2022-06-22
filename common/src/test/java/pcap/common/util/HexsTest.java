/*
 * Copyright (c) 2020-2021 Pcap Project
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
}
