/*
 * Copyright (c) 2020-2022 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import pcap.spi.Timeout;

class DefaultTimeoutTest {

  @Test
  void defaultTimeout() {
    DefaultTimeout timeout = new DefaultTimeout();
    Assertions.assertEquals(1L, timeout.second());
    Assertions.assertEquals(1000000L, timeout.microSecond());
  }

  @Test
  void nanoSecond() {
    DefaultTimeout timeout = new DefaultTimeout(1000000000L, Timeout.Precision.NANO);
    Assertions.assertEquals(1L, timeout.second());
    Assertions.assertEquals(1000000L, timeout.microSecond());
  }

  @Test
  void microSecond() {
    DefaultTimeout timeout = new DefaultTimeout(1000000L, Timeout.Precision.MICRO);
    Assertions.assertEquals(1L, timeout.second());
    Assertions.assertEquals(1000000L, timeout.microSecond());
  }

  @Test
  void nullPrecision() {
    DefaultTimeout timeout = new DefaultTimeout(1000000L, null);
    Assertions.assertEquals(0L, timeout.second());
    Assertions.assertEquals(0L, timeout.microSecond());
  }

  @Test
  void toStringTest() {
    Assertions.assertNotNull(new DefaultTimeout(1000000L, Timeout.Precision.MICRO).toString());
  }

  @Test
  void precisionID() {
    Assertions.assertEquals(0, Timeout.Precision.MICRO.value());
    Assertions.assertEquals(1, Timeout.Precision.NANO.value());
  }
}
