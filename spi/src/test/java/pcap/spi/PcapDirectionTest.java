/*
 * Copyright (c) 2020 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@RunWith(JUnitPlatform.class)
public class PcapDirectionTest {

  @Test
  void directionTest() {
    Assertions.assertEquals(Pcap.Direction.PCAP_D_INOUT, Pcap.Direction.fromString("PCAP_D_INOUT"));
    Assertions.assertEquals(Pcap.Direction.PCAP_D_IN, Pcap.Direction.fromString("PCAP_D_IN"));
    Assertions.assertEquals(Pcap.Direction.PCAP_D_OUT, Pcap.Direction.fromString("PCAP_D_OUT"));
    Assertions.assertEquals(Pcap.Direction.PCAP_D_INOUT, Pcap.Direction.fromString(""));
  }
}
