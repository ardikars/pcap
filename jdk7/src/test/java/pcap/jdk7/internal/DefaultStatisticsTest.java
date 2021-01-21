/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.jdk7.internal;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
public class DefaultStatisticsTest {

  @Test
  void newInstance() {
    DefaultStatistics statistics = new DefaultStatistics();
    Assertions.assertEquals(0, statistics.dropped());
    Assertions.assertEquals(0, statistics.droppedByInterface());
    Assertions.assertEquals(0, statistics.received());

    DefaultStatistics fromPointer = new DefaultStatistics();
    fromPointer.pointer.setInt(DefaultStatistics.PS_RECV_OFFSET, 1);
    fromPointer.pointer.setInt(DefaultStatistics.PS_DROP_OFFSET, 1);
    fromPointer.pointer.setInt(DefaultStatistics.PS_IFDROP_OFFSET, 1);

    Assertions.assertEquals(1, fromPointer.received());
    Assertions.assertEquals(1, fromPointer.dropped());
    Assertions.assertEquals(1, fromPointer.droppedByInterface());

    Native.free(Pointer.nativeValue(fromPointer.pointer));
  }
}
