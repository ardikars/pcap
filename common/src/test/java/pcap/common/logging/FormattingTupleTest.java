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
public class FormattingTupleTest {

  @Test
  public void newInstanceTest() {
    String message = "HELLO {}{}";
    Object[] values = new String[] {"WORLD", "!"};
    FormattingTuple singleArgs = new FormattingTuple(message);
    Assertions.assertEquals(message, singleArgs.getMessage());
    Assertions.assertNull(singleArgs.getArgArray());
    Assertions.assertNull(singleArgs.getThrowable());

    FormattingTuple tripleArgs = new FormattingTuple(message, values, null);
    Assertions.assertEquals(message, tripleArgs.getMessage());
    Assertions.assertEquals(values, tripleArgs.getArgArray());
    Assertions.assertNull(tripleArgs.getThrowable());
  }
}
