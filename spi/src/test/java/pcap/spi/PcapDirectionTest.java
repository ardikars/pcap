/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/** */
@RunWith(JUnitPlatform.class)
class PcapDirectionTest {

  @Test
  void direction() {
    Assertions.assertNotNull(Pcap.Direction.PCAP_D_IN);
    Assertions.assertNotNull(Pcap.Direction.PCAP_D_OUT);
    Assertions.assertNotNull(Pcap.Direction.PCAP_D_INOUT);
  }
}
