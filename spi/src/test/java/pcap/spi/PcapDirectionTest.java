/*
 * Copyright (c) 2020-2022 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/** */
class PcapDirectionTest {

  @Test
  void direction() {
    Assertions.assertNotNull(Pcap.Direction.PCAP_D_IN);
    Assertions.assertNotNull(Pcap.Direction.PCAP_D_OUT);
    Assertions.assertNotNull(Pcap.Direction.PCAP_D_INOUT);
  }
}
