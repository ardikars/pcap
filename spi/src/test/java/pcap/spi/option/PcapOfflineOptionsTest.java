/*
 * Copyright (c) 2020-2022 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.option;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import pcap.spi.Timestamp;

class PcapOfflineOptionsTest {

  @Test
  void setAndGetOptionsTest() {
    Timestamp.Precision tsPrecision = Timestamp.Precision.MICRO;
    DefaultOfflineOptions options = new DefaultOfflineOptions();
    options.timestampPrecision(tsPrecision);
    Assertions.assertEquals(tsPrecision, options.timestampPrecision());
    Assertions.assertNotNull(options.toString());
  }
}
