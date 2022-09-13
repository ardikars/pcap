/*
 * Copyright (c) 2020-2022 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.common.logging;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class Log4j2FactoryTest {

  @Test
  void hasLog4j2Test() {
    Assertions.assertTrue(Log4j2LoggerFactory.hasLog4j2());
  }

  @Test
  void getInstanceTest() {
    Assertions.assertTrue(Log4j2LoggerFactory.getInstance() instanceof Log4j2LoggerFactory);
  }
}
