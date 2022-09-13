/*
 * Copyright (c) 2020-2022 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.common.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/** */
class LongsTest {

  @Test
  void toLongTestBE() {
    long longValue = 9223372036854775807L;
    byte[] bytes = Bytes.toByteArray(longValue);
    long actualValue = Longs.toLong(bytes);
    long actualValueFromOffset = Longs.toLong(bytes, 0);
    Assertions.assertEquals(longValue, actualValue);
    Assertions.assertEquals(longValue, actualValueFromOffset);
  }

  @Test
  void toLongTestLE() {
    long longValue = 9223372036854775807L;
    byte[] bytes = Bytes.toByteArrayLE(longValue);
    long actualValue = Longs.toLongLE(bytes);
    long actualValueFromOffset = Longs.toLongLE(bytes, 0);
    Assertions.assertEquals(longValue, actualValue);
    Assertions.assertEquals(longValue, actualValueFromOffset);
  }
}
