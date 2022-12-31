/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.common.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/** */
class IntegersTest {

  @Test
  void toIntegerTestBE() {
    int intValue = 2147483647;
    byte[] bytes = Bytes.toByteArray(intValue);
    int actualValue = Integers.toInteger(bytes);
    int actualValueFromOffset = Integers.toInteger(bytes, 0);
    Assertions.assertEquals(intValue, actualValue);
    Assertions.assertEquals(intValue, actualValueFromOffset);
  }

  @Test
  void toIntegerTestLE() {
    int intValue = 2147483647;
    byte[] bytes = Bytes.toByteArrayLE(intValue);
    int actualValue = Integers.toIntegerLE(bytes);
    int actualValueFromOffset = Integers.toIntegerLE(bytes, 0);
    Assertions.assertEquals(intValue, actualValue);
    Assertions.assertEquals(intValue, actualValueFromOffset);
  }
}
