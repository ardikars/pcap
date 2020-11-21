/*
 * Copyright (c) 2020 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.jdk7.internal;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
public class EventServiceTest {

  @Test
  void newInstance() {
    Assertions.assertNotNull(EventService.Creator.create());
    Assertions.assertTrue(
        EventService.Creator.newInstance(true) instanceof DefaultWaitForSingleObjectEventService);
    Assertions.assertTrue(
        EventService.Creator.newInstance(false) instanceof DefaultPollEventService);
  }
}
