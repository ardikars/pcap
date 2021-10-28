/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.jdk7.internal;

import com.sun.jna.Pointer;
import org.junit.jupiter.api.Assertions;
import pcap.spi.PacketBuffer;
import pcap.spi.exception.MemoryAccessException;

import java.util.concurrent.atomic.AtomicInteger;

// test for multi threaded, currently is not supported
// @RunWith(JUnitPlatform.class)
class NegativeTest {

  //  @Test
  void multiThreadGuardTest() {
    final AtomicInteger counter = new AtomicInteger();
    final int maxThread = Runtime.getRuntime().availableProcessors() * 20;
    final PacketBuffer[] memories = new PacketBuffer[maxThread];
    for (int i = 0; i < memories.length; i++) {
      memories[i] = DefaultPacketBuffer.PacketBufferManager.allocate(4);
      memories[i].setInt(0, Integer.MAX_VALUE);
      Assertions.assertEquals(Integer.MAX_VALUE, memories[i].getInt(0));
    }
    final Thread[] getterThreads = new Thread[maxThread];
    for (int i = 0; i < getterThreads.length; i++) {
      final int finalI = i;
      getterThreads[i] =
          new Thread(
              new Runnable() {
                @Override
                public void run() {
                  try {
                    if (Integer.MAX_VALUE != memories[finalI].getInt(0)) {
                      DefaultPacketBuffer.FinalizablePacketBuffer memory =
                          (DefaultPacketBuffer.FinalizablePacketBuffer) memories[finalI];
                      throw new AssertionError(
                          String.format("Invalid value (%d).", Pointer.nativeValue(memory.buffer)));
                    }
                  } catch (Throwable e) {
                    if (!(e instanceof MemoryAccessException)) {
                      throw new AssertionError(e.getMessage());
                    }
                  }
                }
              });
    }
    final Thread[] releaseThreads = new Thread[maxThread];
    for (int i = 0; i < releaseThreads.length; i++) {
      final int finalI = i;
      releaseThreads[i] =
          new Thread(
              new Runnable() {
                @Override
                public void run() {
                  memories[finalI].release();
                  counter.incrementAndGet();
                }
              });
    }
    for (int i = 0; i < maxThread; i++) {
      getterThreads[i].start();
      releaseThreads[i].start();
    }
    try {
      Thread.sleep(5000);
    } catch (InterruptedException e) {
      //
    }
  }
}
