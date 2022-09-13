/*
 * Copyright (c) 2020-2022 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/** */
class TimestampTest {

  @Test
  void typeTest() {
    Assertions.assertEquals(0, Timestamp.Type.HOST.value());
    Assertions.assertEquals(1, Timestamp.Type.HOST_LOWPREC.value());
    Assertions.assertEquals(2, Timestamp.Type.HOST_HIPREC.value());
    Assertions.assertEquals(3, Timestamp.Type.ADAPTER.value());
    Assertions.assertEquals(4, Timestamp.Type.ADAPTER_UNSYNCED.value());
  }

  @Test
  void precisionTest() {
    Assertions.assertEquals(0, Timestamp.Precision.MICRO.value());
    Assertions.assertEquals(1, Timestamp.Precision.NANO.value());
  }
}
