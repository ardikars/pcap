/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi;

import java.nio.channels.SelectionKey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
public class SelectionTest {

  @Test
  void readWrite() {
    Assertions.assertEquals(SelectionKey.OP_READ, Selection.OPERATION_READ);
    Assertions.assertEquals(SelectionKey.OP_WRITE, Selection.OPERATION_WRITE);
  }
}
