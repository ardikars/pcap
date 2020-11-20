/*
 * Copyright (c) 2020 Pcap <contact@pcap.ardikars.com>
 * SPDX-License-Identifier: MIT
 */
package pcap.common.util;

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
    short actualValueFromOffset = Shorts.toShort(bytes, 0);
    Assertions.assertEquals(value, actualValue);
    Assertions.assertEquals(value, actualValueFromOffset);
  }

  @Test
  public void toShortTestLE() {
    short shortValue = (short) 65533;
    byte[] bytes = Bytes.toByteArrayLE(shortValue);
    short actualValue = Shorts.toShortLE(bytes);
    short actualValueFromOffset = Shorts.toShortLE(bytes, 0);
    Assertions.assertEquals(shortValue, actualValue);
    Assertions.assertEquals(shortValue, actualValueFromOffset);
  }
}
