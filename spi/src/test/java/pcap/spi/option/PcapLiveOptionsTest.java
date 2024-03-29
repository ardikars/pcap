/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.option;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import pcap.spi.Timestamp;

class PcapLiveOptionsTest {

  @Test
  void setAndGetOptionsTest() {
    int snapshotLength = 2048;
    boolean promiscuous = true;
    boolean rfmon = false;
    boolean immediate = true;
    int timeout = 2000;
    int bufferSize = 4096;
    Timestamp.Type tsType = Timestamp.Type.HOST;
    Timestamp.Precision tsPrecision = Timestamp.Precision.MICRO;
    DefaultLiveOptions options = new DefaultLiveOptions();
    options.snapshotLength(snapshotLength);
    options.promiscuous(promiscuous);
    options.rfmon(rfmon);
    options.timeout(timeout);
    options.timestampType(tsType);
    options.timestampPrecision(tsPrecision);
    options.immediate(immediate);
    options.bufferSize(bufferSize);
    Assertions.assertEquals(snapshotLength, options.snapshotLength());
    Assertions.assertEquals(promiscuous, options.isPromiscuous());
    Assertions.assertEquals(rfmon, options.isRfmon());
    Assertions.assertEquals(timeout, options.timeout());
    Assertions.assertEquals(tsType, options.timestampType());
    Assertions.assertEquals(tsPrecision, options.timestampPrecision());
    Assertions.assertEquals(immediate, options.isImmediate());
    Assertions.assertEquals(bufferSize, options.bufferSize());
    Assertions.assertNotNull(options.toString());
  }
}
