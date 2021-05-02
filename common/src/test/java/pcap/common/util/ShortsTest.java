/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.common.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/** */
@RunWith(JUnitPlatform.class)
class ShortsTest {

  @Test
  void toShortTestBE() {
    short value = (short) 65533;
    byte[] bytes = Bytes.toByteArray(value);
    short actualValue = Shorts.toShort(bytes);
    short actualValueFromOffset = Shorts.toShort(bytes, 0);
    Assertions.assertEquals(value, actualValue);
    Assertions.assertEquals(value, actualValueFromOffset);
  }

  @Test
  void toShortTestLE() {
    short shortValue = (short) 65533;
    byte[] bytes = Bytes.toByteArrayLE(shortValue);
    short actualValue = Shorts.toShortLE(bytes);
    short actualValueFromOffset = Shorts.toShortLE(bytes, 0);
    Assertions.assertEquals(shortValue, actualValue);
    Assertions.assertEquals(shortValue, actualValueFromOffset);
  }
}
