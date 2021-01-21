/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
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
public class DefaultPacketHeaderTest {

  @Test
  void newInstance() {
    DefaultPacketHeader packetHeader = new DefaultPacketHeader();
    Assertions.assertEquals(0, packetHeader.timestamp().second());
    Assertions.assertEquals(0, packetHeader.timestamp().microSecond());
    Assertions.assertEquals(0, packetHeader.captureLength());
    Assertions.assertEquals(0, packetHeader.length());

    Pointer pointer = new Pointer(Native.malloc(DefaultPacketHeader.SIZEOF));
    pointer.setNativeLong(DefaultTimestamp.TV_SEC_OFFSET, new NativeLong(1L));
    pointer.setNativeLong(DefaultTimestamp.TV_USEC_OFFSET, new NativeLong(2L));
    pointer.setInt(DefaultPacketHeader.CAPLEN_OFFSET, 3);
    pointer.setInt(DefaultPacketHeader.LEN_OFFSET, 4);

    DefaultPacketHeader fromPointer = new DefaultPacketHeader(pointer);
    Assertions.assertEquals(1, fromPointer.timestamp().second());
    Assertions.assertEquals(2, fromPointer.timestamp().microSecond());
    Assertions.assertEquals(3, fromPointer.captureLength());
    Assertions.assertEquals(4, fromPointer.length());

    Native.free(Pointer.nativeValue(pointer));
  }

  @Test
  void useReference() {
    long address = Native.malloc(DefaultPacketHeader.SIZEOF);
    Pointer pointer = new Pointer(address);
    pointer.setNativeLong(DefaultTimestamp.TV_SEC_OFFSET, new NativeLong(1L));
    pointer.setNativeLong(DefaultTimestamp.TV_USEC_OFFSET, new NativeLong(2L));
    pointer.setInt(DefaultPacketHeader.CAPLEN_OFFSET, 3);
    pointer.setInt(DefaultPacketHeader.LEN_OFFSET, 4);

    DefaultPacketHeader header = new DefaultPacketHeader();
    header.reference.setValue(pointer);
    header.useReference();

    Assertions.assertEquals(1, header.timestamp().second());
    Assertions.assertEquals(2, header.timestamp().microSecond());
    Assertions.assertEquals(3, header.captureLength());
    Assertions.assertEquals(4, header.length());

    Native.free(address);
  }
}
