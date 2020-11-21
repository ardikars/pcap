/*
 * Copyright (c) 2020 Pcap <contact@pcap.ardikars.com>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.common.logging;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
public class Log4j2FactoryTest {

  @Test
  public void hasLog4j2Test() {
    Assertions.assertTrue(Log4j2LoggerFactory.hasLog4j2());
  }

  @Test
  public void getInstanceTest() {
    Assertions.assertTrue(Log4j2LoggerFactory.getInstance() instanceof Log4j2LoggerFactory);
  }
}
