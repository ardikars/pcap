/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.common.logging;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class FormattingTupleTest {

  @Test
  void newInstanceTest() {
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
