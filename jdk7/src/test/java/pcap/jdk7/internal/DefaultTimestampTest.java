/*
 * Copyright (c) 2020 Pcap <contact@pcap.ardikars.com>
 * SPDX-License-Identifier: MIT
 */
package pcap.jdk7.internal;

import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
public class DefaultTimestampTest {

  @Test
  void newInstance() {
    DefaultTimestamp timestamp = new DefaultTimestamp();

    Assertions.assertEquals(0, timestamp.second());
    Assertions.assertEquals(0, timestamp.microSecond());

    Pointer pointer = new Pointer(Native.malloc(DefaultTimestamp.SIZEOF));
    pointer.setNativeLong(DefaultTimestamp.TV_SEC_OFFSET, new NativeLong(1));
    pointer.setNativeLong(DefaultTimestamp.TV_USEC_OFFSET, new NativeLong(2));

    DefaultTimestamp fromPointer = new DefaultTimestamp(pointer);
    Assertions.assertEquals(1, fromPointer.second());
    Assertions.assertEquals(2, fromPointer.microSecond());

    Native.free(Pointer.nativeValue(pointer));
  }
}
