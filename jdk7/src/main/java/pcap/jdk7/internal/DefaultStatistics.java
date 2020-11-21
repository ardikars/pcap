/*
 * Copyright (c) 2020 Pcap <contact@pcap.ardikars.com>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.jdk7.internal;

import pcap.spi.Statistics;

class DefaultStatistics implements Statistics {

  static final int PS_RECV_OFFSET = 0;
  static final int PS_DROP_OFFSET = 4;
  static final int PS_IFDROP_OFFSET = PS_DROP_OFFSET + 4;
  static final int BS_CAPT_OFFSET = PS_IFDROP_OFFSET + 4;
  static final int SIZEOF = BS_CAPT_OFFSET + 4;

  com.sun.jna.Pointer pointer;

  /** Don't forget to deallocate the buffer */
  DefaultStatistics() {
    this.pointer = new com.sun.jna.Pointer(com.sun.jna.Native.malloc(DefaultStatistics.SIZEOF));
    this.pointer.setInt(PS_RECV_OFFSET, 0);
    this.pointer.setInt(PS_DROP_OFFSET, 0);
    this.pointer.setInt(PS_IFDROP_OFFSET, 0);
    this.pointer.setInt(BS_CAPT_OFFSET, 0);
  }

  @Override
  public int received() {
    return pointer.getInt(PS_RECV_OFFSET);
  }

  @Override
  public int dropped() {
    return pointer.getInt(PS_DROP_OFFSET);
  }

  @Override
  public int droppedByInterface() {
    return pointer.getInt(PS_IFDROP_OFFSET);
  }
}
