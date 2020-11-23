/*
 * Copyright (c) 2020 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.jdk7.internal;

import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import java.lang.ref.ReferenceQueue;
import java.lang.reflect.InvocationTargetException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.spi.Packet;
import pcap.spi.PacketBuffer;
import pcap.spi.exception.MemoryAccessException;
import pcap.spi.exception.MemoryLeakException;

@RunWith(JUnitPlatform.class)
public class DefaultPacketBufferTest {

  private static final int BYTE_BYTES = 1;
  private static final int SHORT_BYTES = 2;
  private static final int INTEGER_BYTES = 4;
  private static final int LONG_BYTES = 8;

  @Test
  void useMemory() {
    Pointer hdrPtr = new Pointer(Native.malloc(DefaultPacketHeader.SIZEOF));
    hdrPtr.setNativeLong(DefaultTimestamp.TV_SEC_OFFSET, new NativeLong(0));
    hdrPtr.setNativeLong(DefaultTimestamp.TV_USEC_OFFSET, new NativeLong(0));
    hdrPtr.setInt(DefaultPacketHeader.CAPLEN_OFFSET, 4);
    hdrPtr.setInt(DefaultPacketHeader.LEN_OFFSET, 4);

    DefaultPacketHeader header = new DefaultPacketHeader(hdrPtr);

    Pointer bufPtr = new Pointer(Native.malloc(header.captureLength()));
    DefaultPacketBuffer buffer = new DefaultPacketBuffer();
    buffer.reference.setValue(bufPtr);
    buffer.useReference(header);

    Native.free(Pointer.nativeValue(hdrPtr));
    Native.free(Pointer.nativeValue(bufPtr));
  }

  @Test
  void capacity() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    Assertions.assertEquals(SHORT_BYTES, smallBuffer.capacity());
    Assertions.assertEquals(INTEGER_BYTES, mediumBuffer.capacity());
    Assertions.assertEquals(LONG_BYTES, largeBuffer.capacity());

    largeBuffer =
        largeBuffer
            .setIndex(largeBuffer.capacity(), largeBuffer.capacity())
            .markReaderIndex()
            .markWriterIndex()
            .capacity(largeBuffer.capacity() * SHORT_BYTES);
    Assertions.assertEquals(LONG_BYTES * SHORT_BYTES, largeBuffer.capacity());
    Assertions.assertEquals(largeBuffer.readerIndex(), largeBuffer.readerIndex());
    Assertions.assertEquals(largeBuffer.writerIndex(), largeBuffer.writerIndex());
    largeBuffer =
        largeBuffer
            .setIndex(largeBuffer.capacity(), largeBuffer.capacity())
            .markReaderIndex()
            .markWriterIndex()
            .capacity(LONG_BYTES);
    Assertions.assertEquals(LONG_BYTES, largeBuffer.capacity());
    Assertions.assertEquals(LONG_BYTES, largeBuffer.readerIndex());
    Assertions.assertEquals(LONG_BYTES, largeBuffer.writerIndex());

    largeBuffer =
        largeBuffer
            .capacity(largeBuffer.capacity() * SHORT_BYTES)
            .setIndex(BYTE_BYTES, SHORT_BYTES)
            .capacity(LONG_BYTES);
    Assertions.assertEquals(LONG_BYTES, largeBuffer.capacity());
    Assertions.assertEquals(BYTE_BYTES, largeBuffer.readerIndex());
    Assertions.assertEquals(SHORT_BYTES, largeBuffer.writerIndex());

    DefaultPacketBuffer buffer = new DefaultPacketBuffer();
    Assertions.assertNull(buffer.buffer);
    buffer = (DefaultPacketBuffer) buffer.capacity(LONG_BYTES);
    Assertions.assertNotNull(buffer);
    Assertions.assertEquals(LONG_BYTES, buffer.capacity());

    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            new DefaultPacketBuffer().capacity(0);
          }
        });
    Assertions.assertTrue(buffer.release());

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void readerIndex() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    Assertions.assertEquals(0, smallBuffer.readerIndex());
    Assertions.assertEquals(0, mediumBuffer.readerIndex());
    Assertions.assertEquals(0, largeBuffer.readerIndex());
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.readerIndex(SHORT_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.readerIndex(INTEGER_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.readerIndex(LONG_BYTES);
          }
        });
    smallBuffer.writerIndex(SHORT_BYTES);
    mediumBuffer.writerIndex(INTEGER_BYTES);
    largeBuffer.writerIndex(LONG_BYTES);
    Assertions.assertEquals(SHORT_BYTES, smallBuffer.readerIndex(SHORT_BYTES).readerIndex());
    Assertions.assertEquals(INTEGER_BYTES, mediumBuffer.readerIndex(INTEGER_BYTES).readerIndex());
    Assertions.assertEquals(LONG_BYTES, largeBuffer.readerIndex(LONG_BYTES).readerIndex());
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.readerIndex(-BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.readerIndex(-BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.readerIndex(-BYTE_BYTES);
          }
        });

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void writerIndex() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    Assertions.assertEquals(0, smallBuffer.writerIndex());
    Assertions.assertEquals(0, mediumBuffer.writerIndex());
    Assertions.assertEquals(0, largeBuffer.writerIndex());
    Assertions.assertEquals(SHORT_BYTES, smallBuffer.writerIndex(SHORT_BYTES).writerIndex());
    Assertions.assertEquals(INTEGER_BYTES, mediumBuffer.writerIndex(INTEGER_BYTES).writerIndex());
    Assertions.assertEquals(LONG_BYTES, largeBuffer.writerIndex(LONG_BYTES).writerIndex());
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.writerIndex(-BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.writerIndex(-BYTE_BYTES);
          }
        });

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.writerIndex(-BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.writerIndex(SHORT_BYTES + BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.writerIndex(INTEGER_BYTES + BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.writerIndex(LONG_BYTES + BYTE_BYTES);
          }
        });
    smallBuffer.readerIndex(SHORT_BYTES);
    mediumBuffer.readerIndex(INTEGER_BYTES);
    largeBuffer.readerIndex(LONG_BYTES);
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.writerIndex(SHORT_BYTES - BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.writerIndex(INTEGER_BYTES - BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.writerIndex(LONG_BYTES - BYTE_BYTES);
          }
        });

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void setIndex() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    smallBuffer.setIndex(SHORT_BYTES, SHORT_BYTES);
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.setIndex(SHORT_BYTES, SHORT_BYTES - BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.setIndex(SHORT_BYTES, SHORT_BYTES + BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.setIndex(SHORT_BYTES, -BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.setIndex(SHORT_BYTES, BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.setIndex(-BYTE_BYTES, SHORT_BYTES);
          }
        });
    //
    mediumBuffer.setIndex(INTEGER_BYTES, INTEGER_BYTES);
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.setIndex(INTEGER_BYTES, INTEGER_BYTES - BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.setIndex(INTEGER_BYTES, INTEGER_BYTES + BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.setIndex(INTEGER_BYTES, -BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.setIndex(INTEGER_BYTES, BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.setIndex(-BYTE_BYTES, INTEGER_BYTES);
          }
        });
    //
    largeBuffer.setIndex(LONG_BYTES, LONG_BYTES);
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setIndex(LONG_BYTES, LONG_BYTES - BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setIndex(LONG_BYTES, LONG_BYTES + BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setIndex(LONG_BYTES, -BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setIndex(LONG_BYTES, BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setIndex(-BYTE_BYTES, LONG_BYTES);
          }
        });

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void readableBytes() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    Assertions.assertEquals(0, smallBuffer.readableBytes());
    Assertions.assertEquals(SHORT_BYTES, smallBuffer.writerIndex(SHORT_BYTES).readableBytes());
    Assertions.assertEquals(0, mediumBuffer.readableBytes());
    Assertions.assertEquals(INTEGER_BYTES, mediumBuffer.writerIndex(INTEGER_BYTES).readableBytes());
    Assertions.assertEquals(0, largeBuffer.readableBytes());
    Assertions.assertEquals(LONG_BYTES, largeBuffer.writerIndex(LONG_BYTES).readableBytes());

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void writableBytes() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    Assertions.assertEquals(SHORT_BYTES, smallBuffer.writableBytes());
    Assertions.assertEquals(0, smallBuffer.writerIndex(SHORT_BYTES).writableBytes());
    Assertions.assertEquals(INTEGER_BYTES, mediumBuffer.writableBytes());
    Assertions.assertEquals(0, mediumBuffer.writerIndex(INTEGER_BYTES).writableBytes());
    Assertions.assertEquals(LONG_BYTES, largeBuffer.writableBytes());
    Assertions.assertEquals(0, largeBuffer.writerIndex(LONG_BYTES).writableBytes());

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void isReadable() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    Assertions.assertFalse(smallBuffer.isReadable());
    Assertions.assertTrue(smallBuffer.writerIndex(SHORT_BYTES).isReadable());
    Assertions.assertFalse(smallBuffer.isReadable(SHORT_BYTES + BYTE_BYTES));
    Assertions.assertTrue(smallBuffer.setIndex(BYTE_BYTES, SHORT_BYTES).isReadable(BYTE_BYTES));
    Assertions.assertFalse(smallBuffer.isReadable(-BYTE_BYTES));
    Assertions.assertFalse(smallBuffer.writerIndex(SHORT_BYTES).isReadable(-BYTE_BYTES));

    Assertions.assertFalse(mediumBuffer.isReadable());
    Assertions.assertTrue(mediumBuffer.writerIndex(INTEGER_BYTES).isReadable());
    Assertions.assertFalse(mediumBuffer.isReadable(INTEGER_BYTES + BYTE_BYTES));
    Assertions.assertTrue(mediumBuffer.setIndex(BYTE_BYTES, INTEGER_BYTES).isReadable(BYTE_BYTES));
    Assertions.assertFalse(mediumBuffer.isReadable(-BYTE_BYTES));
    Assertions.assertFalse(mediumBuffer.writerIndex(INTEGER_BYTES).isReadable(-BYTE_BYTES));

    Assertions.assertFalse(largeBuffer.isReadable());
    Assertions.assertTrue(largeBuffer.writerIndex(LONG_BYTES).isReadable());
    Assertions.assertFalse(largeBuffer.isReadable(LONG_BYTES + BYTE_BYTES));
    Assertions.assertTrue(largeBuffer.setByte(BYTE_BYTES, LONG_BYTES).isReadable(BYTE_BYTES));
    Assertions.assertFalse(largeBuffer.isReadable(-BYTE_BYTES));
    Assertions.assertFalse(largeBuffer.writerIndex(LONG_BYTES).isReadable(-BYTE_BYTES));

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void isWritable() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    Assertions.assertTrue(smallBuffer.isWritable());
    Assertions.assertFalse(smallBuffer.setIndex(SHORT_BYTES, SHORT_BYTES).isWritable());
    Assertions.assertFalse(smallBuffer.setIndex(0, 0).isWritable(SHORT_BYTES + BYTE_BYTES));
    Assertions.assertTrue(smallBuffer.setIndex(BYTE_BYTES, BYTE_BYTES).isWritable(BYTE_BYTES));
    Assertions.assertFalse(smallBuffer.setIndex(0, 0).isWritable(-BYTE_BYTES));
    Assertions.assertFalse(smallBuffer.setIndex(0, SHORT_BYTES).isWritable(-BYTE_BYTES));

    Assertions.assertTrue(mediumBuffer.isWritable());
    Assertions.assertFalse(mediumBuffer.setIndex(INTEGER_BYTES, INTEGER_BYTES).isWritable());
    Assertions.assertFalse(mediumBuffer.setIndex(0, 0).isWritable(INTEGER_BYTES + BYTE_BYTES));
    Assertions.assertTrue(mediumBuffer.setIndex(BYTE_BYTES, BYTE_BYTES).isWritable(BYTE_BYTES));
    Assertions.assertFalse(mediumBuffer.setIndex(0, 0).isWritable(-BYTE_BYTES));
    Assertions.assertFalse(mediumBuffer.setIndex(0, INTEGER_BYTES).isWritable(-BYTE_BYTES));

    Assertions.assertTrue(largeBuffer.isWritable());
    Assertions.assertFalse(largeBuffer.setIndex(LONG_BYTES, LONG_BYTES).isWritable());
    Assertions.assertFalse(largeBuffer.setIndex(0, 0).isWritable(LONG_BYTES + BYTE_BYTES));
    Assertions.assertTrue(largeBuffer.setIndex(BYTE_BYTES, BYTE_BYTES).isWritable(BYTE_BYTES));
    Assertions.assertFalse(largeBuffer.setIndex(0, 0).isWritable(-BYTE_BYTES));
    Assertions.assertFalse(largeBuffer.setIndex(0, LONG_BYTES).isWritable(-BYTE_BYTES));

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void markReader() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    Assertions.assertEquals(0, smallBuffer.markReaderIndex().resetReaderIndex().readerIndex());
    Assertions.assertEquals(
        BYTE_BYTES,
        smallBuffer
            .setIndex(BYTE_BYTES, SHORT_BYTES)
            .markReaderIndex()
            .readerIndex(SHORT_BYTES)
            .resetReaderIndex()
            .readerIndex());
    Assertions.assertEquals(0, mediumBuffer.markReaderIndex().resetReaderIndex().readerIndex());
    Assertions.assertEquals(
        BYTE_BYTES,
        mediumBuffer
            .setIndex(BYTE_BYTES, INTEGER_BYTES)
            .markReaderIndex()
            .readerIndex(INTEGER_BYTES)
            .resetReaderIndex()
            .readerIndex());
    Assertions.assertEquals(0, largeBuffer.markReaderIndex().resetReaderIndex().readerIndex());
    Assertions.assertEquals(
        BYTE_BYTES,
        largeBuffer
            .setIndex(BYTE_BYTES, LONG_BYTES)
            .markReaderIndex()
            .readerIndex(LONG_BYTES)
            .resetReaderIndex()
            .readerIndex());

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void markWriter() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    Assertions.assertEquals(0, smallBuffer.markReaderIndex().writerIndex());
    Assertions.assertEquals(
        BYTE_BYTES,
        smallBuffer
            .setIndex(BYTE_BYTES, BYTE_BYTES)
            .markWriterIndex()
            .writerIndex(SHORT_BYTES)
            .resetWriterIndex()
            .writerIndex());
    Assertions.assertEquals(0, mediumBuffer.markReaderIndex().writerIndex());
    Assertions.assertEquals(
        BYTE_BYTES,
        mediumBuffer
            .setIndex(BYTE_BYTES, BYTE_BYTES)
            .markWriterIndex()
            .writerIndex(INTEGER_BYTES)
            .resetWriterIndex()
            .writerIndex());
    Assertions.assertEquals(0, largeBuffer.markReaderIndex().writerIndex());
    Assertions.assertEquals(
        BYTE_BYTES,
        largeBuffer
            .setIndex(BYTE_BYTES, BYTE_BYTES)
            .markWriterIndex()
            .writerIndex(SHORT_BYTES)
            .resetWriterIndex()
            .writerIndex());

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void ensureWritable() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    smallBuffer.ensureWritable(BYTE_BYTES);
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.ensureWritable(-BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.setIndex(SHORT_BYTES, SHORT_BYTES).ensureWritable(BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.setIndex(0, 0).ensureWritable(SHORT_BYTES + BYTE_BYTES);
          }
        });
    //
    mediumBuffer.ensureWritable(BYTE_BYTES);
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.ensureWritable(-BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.setIndex(INTEGER_BYTES, INTEGER_BYTES).ensureWritable(BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.setIndex(0, 0).ensureWritable(INTEGER_BYTES + BYTE_BYTES);
          }
        });
    //
    largeBuffer.ensureWritable(BYTE_BYTES);
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.ensureWritable(-BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setIndex(LONG_BYTES, LONG_BYTES).ensureWritable(BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setIndex(0, 0).ensureWritable(LONG_BYTES + BYTE_BYTES);
          }
        });

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void getBoolean() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    for (int i = 0; i < SHORT_BYTES; i++) {
      smallBuffer.setByte(i, i);
      if (i < BYTE_BYTES) {
        Assertions.assertFalse(smallBuffer.getBoolean(i));
      } else {
        Assertions.assertTrue(smallBuffer.getBoolean(i));
      }
    }
    for (int i = 0; i < INTEGER_BYTES; i++) {
      mediumBuffer.setByte(i, i);
      if (i < BYTE_BYTES) {
        Assertions.assertFalse(mediumBuffer.getBoolean(i));
      } else {
        Assertions.assertTrue(mediumBuffer.getBoolean(i));
      }
    }
    for (int i = 0; i < LONG_BYTES; i++) {
      largeBuffer.setByte(i, i);
      if (i < BYTE_BYTES) {
        Assertions.assertFalse(largeBuffer.getBoolean(i));
      } else {
        Assertions.assertTrue(largeBuffer.getBoolean(i));
      }
    }

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void getUnsignedByte() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    for (int i = 0; i < SHORT_BYTES; i++) {
      smallBuffer.setByte(i, 0xFF);
      Assertions.assertEquals(0xFF, smallBuffer.getUnsignedByte(i));
    }
    for (int i = 0; i < INTEGER_BYTES; i++) {
      mediumBuffer.setByte(i, 0xFF);
      Assertions.assertEquals(0xFF, mediumBuffer.getUnsignedByte(i));
    }
    for (int i = 0; i < LONG_BYTES; i++) {
      largeBuffer.setByte(i, 0xFF);
      Assertions.assertEquals(0xFF, largeBuffer.getUnsignedByte(i));
    }

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void getShortRE() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    for (int i = 0; i < SHORT_BYTES / SHORT_BYTES; i++) {
      smallBuffer.setShort(i, i);
      Assertions.assertEquals(Short.reverseBytes((short) i), smallBuffer.getShortRE(i));
    }
    for (int i = 0; i < INTEGER_BYTES / SHORT_BYTES; i++) {
      mediumBuffer.setShort(i, i);
      Assertions.assertEquals(Short.reverseBytes((short) i), mediumBuffer.getShortRE(i));
    }
    for (int i = 0; i < LONG_BYTES / SHORT_BYTES; i++) {
      largeBuffer.setShort(i, i);
      Assertions.assertEquals(Short.reverseBytes((short) i), largeBuffer.getShortRE(i));
    }

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void getUnsignedShort() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    for (int i = 0; i < SHORT_BYTES / SHORT_BYTES; i++) {
      smallBuffer.setShort(i, 0xFFFF);
      Assertions.assertEquals(0xFFFF, smallBuffer.getUnsignedShort(i));
    }
    for (int i = 0; i < INTEGER_BYTES / SHORT_BYTES; i++) {
      mediumBuffer.setShort(i, 0xFFFF);
      Assertions.assertEquals(0xFFFF, mediumBuffer.getUnsignedShort(i));
    }
    for (int i = 0; i < LONG_BYTES / SHORT_BYTES; i++) {
      largeBuffer.setShort(i, 0xFFFF);
      Assertions.assertEquals(0xFFFF, largeBuffer.getUnsignedShort(i));
    }

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void getUnsignedShortRE() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    for (int i = 0; i < SHORT_BYTES / SHORT_BYTES; i++) {
      smallBuffer.setShort(i, 0xFFFF);
      Assertions.assertEquals(
          Short.reverseBytes((short) 0xFFFF), smallBuffer.getUnsignedShortRE(i));
    }
    for (int i = 0; i < INTEGER_BYTES / SHORT_BYTES; i++) {
      mediumBuffer.setShort(i, 0xFFFF);
      Assertions.assertEquals(
          Short.reverseBytes((short) 0xFFFF), mediumBuffer.getUnsignedShortRE(i));
    }
    for (int i = 0; i < LONG_BYTES / SHORT_BYTES; i++) {
      largeBuffer.setShort(i, 0xFFFF);
      Assertions.assertEquals(
          Short.reverseBytes((short) 0xFFFF), largeBuffer.getUnsignedShortRE(i));
    }

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void getIntRE() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    for (int i = 0; i < INTEGER_BYTES / INTEGER_BYTES; i++) {
      mediumBuffer.setInt(i, i);
      Assertions.assertEquals(Integer.reverseBytes(i), mediumBuffer.getIntRE(i));
    }
    for (int i = 0; i < LONG_BYTES / INTEGER_BYTES; i++) {
      largeBuffer.setInt(i, i);
      Assertions.assertEquals(Integer.reverseBytes(i), largeBuffer.getIntRE(i));
    }

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void getUnsignedInt() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    for (int i = 0; i < INTEGER_BYTES / INTEGER_BYTES; i++) {
      mediumBuffer.setInt(i, 0xFFFFFFFF);
      Assertions.assertEquals(0xFFFFFFFFL, mediumBuffer.getUnsignedInt(i));
    }
    for (int i = 0; i < LONG_BYTES / INTEGER_BYTES; i++) {
      largeBuffer.setInt(i, 0xFFFFFFFF);
      Assertions.assertEquals(0xFFFFFFFFL, largeBuffer.getUnsignedInt(i));
    }

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void getUnsignedIntRE() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    for (int i = 0; i < INTEGER_BYTES / INTEGER_BYTES; i++) {
      mediumBuffer.setInt(i, 0xFFFFFFFF);
      Assertions.assertEquals(Integer.reverseBytes(0xFFFFFFFF), mediumBuffer.getUnsignedIntRE(i));
    }
    for (int i = 0; i < LONG_BYTES / INTEGER_BYTES; i++) {
      largeBuffer.setInt(i, 0xFFFFFFFF);
      Assertions.assertEquals(Integer.reverseBytes(0xFFFFFFFF), largeBuffer.getUnsignedIntRE(i));
    }

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void getLongRE() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    for (int i = 0; i < LONG_BYTES / LONG_BYTES; i++) {
      largeBuffer.setLong(i, 0xFFFFFFFFFFFFFFFFL);
      Assertions.assertEquals(Long.reverseBytes(0xFFFFFFFFFFFFFFFFL), largeBuffer.getLongRE(i));
    }

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void getFloat() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    for (int i = 0; i < INTEGER_BYTES / INTEGER_BYTES; i++) {
      mediumBuffer.setFloat(i, i + 0.5F);
      Assertions.assertEquals(i + 0.5F, mediumBuffer.getFloat(i));
    }
    for (int i = 0; i < LONG_BYTES / INTEGER_BYTES; i++) {
      largeBuffer.setFloat(i, i + 0.5F);
      Assertions.assertEquals(i + 0.5F, largeBuffer.getFloat(i));
    }

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void getFloatRE() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    for (int i = 0; i < INTEGER_BYTES / INTEGER_BYTES; i++) {
      mediumBuffer.setFloat(i, i + 0.5F);
      Assertions.assertEquals(
          Float.intBitsToFloat(mediumBuffer.getIntRE(i)), mediumBuffer.getFloatRE(i));
    }
    for (int i = 0; i < LONG_BYTES / INTEGER_BYTES; i++) {
      largeBuffer.setFloat(i, i + 0.5F);
      Assertions.assertEquals(
          Float.intBitsToFloat(largeBuffer.getIntRE(i)), largeBuffer.getFloatRE(i));
    }

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void getDouble() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    for (int i = 0; i < LONG_BYTES / LONG_BYTES; i++) {
      largeBuffer.setDouble(i, i + 0.5D);
      Assertions.assertEquals(i + 0.5D, largeBuffer.getDouble(i));
    }

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void getDoubleRE() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    for (int i = 0; i < LONG_BYTES / LONG_BYTES; i++) {
      largeBuffer.setDouble(i, i + 0.5D);
      Assertions.assertEquals(
          Double.longBitsToDouble(largeBuffer.getLongRE(i)), largeBuffer.getDoubleRE(i));
    }

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void getBytes() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    for (int i = 0; i < SHORT_BYTES; i++) {
      smallBuffer.setByte(i, i);
      Assertions.assertEquals(i, smallBuffer.getByte(i));
    }
    for (int i = 0; i < INTEGER_BYTES; i++) {
      mediumBuffer.setByte(i, i);
      Assertions.assertEquals(i, mediumBuffer.getByte(i));
    }

    smallBuffer.getBytes(0, largeBuffer, SHORT_BYTES);
    mediumBuffer.getBytes(0, largeBuffer, INTEGER_BYTES);
    smallBuffer.getBytes(0, largeBuffer, SHORT_BYTES);
    Assertions.assertEquals(0, largeBuffer.getByte(0));
    Assertions.assertEquals(1, largeBuffer.getByte(1));
    Assertions.assertEquals(0, largeBuffer.getByte(2));
    Assertions.assertEquals(1, largeBuffer.getByte(3));
    Assertions.assertEquals(2, largeBuffer.getByte(4));
    Assertions.assertEquals(3, largeBuffer.getByte(5));
    Assertions.assertEquals(0, largeBuffer.getByte(6));
    Assertions.assertEquals(1, largeBuffer.getByte(7));

    byte[] largeBytes = new byte[LONG_BYTES];
    largeBuffer.resetWriterIndex();
    smallBuffer.getBytes(0, largeBytes, 0, SHORT_BYTES);
    mediumBuffer.getBytes(0, largeBytes, SHORT_BYTES, INTEGER_BYTES);
    smallBuffer.getBytes(0, largeBytes, INTEGER_BYTES + SHORT_BYTES, SHORT_BYTES);
    Assertions.assertEquals(largeBytes[0], largeBuffer.getByte(0));
    Assertions.assertEquals(largeBytes[1], largeBuffer.getByte(1));
    Assertions.assertEquals(largeBytes[2], largeBuffer.getByte(2));
    Assertions.assertEquals(largeBytes[3], largeBuffer.getByte(3));
    Assertions.assertEquals(largeBytes[4], largeBuffer.getByte(4));
    Assertions.assertEquals(largeBytes[5], largeBuffer.getByte(5));
    Assertions.assertEquals(largeBytes[6], largeBuffer.getByte(6));
    Assertions.assertEquals(largeBytes[7], largeBuffer.getByte(7));

    byte[] bufBytes = new byte[LONG_BYTES];
    largeBuffer.getBytes(0, bufBytes);
    Assertions.assertArrayEquals(largeBytes, bufBytes);

    PacketBuffer newBuf = DefaultPacketBuffer.PacketBufferManager.allocate(largeBuffer.capacity());

    largeBuffer.getBytes(0, newBuf);
    for (int i = 0; i < newBuf.capacity(); i++) {
      Assertions.assertEquals(newBuf.getByte(i), largeBuffer.getByte(i));
    }
    Assertions.assertTrue(newBuf.release());

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.getBytes(0, smallBuffer.writerIndex(SHORT_BYTES), 0, LONG_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.getBytes(0, new byte[] {0, 0}, 0, LONG_BYTES);
          }
        });

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void getCharSequace() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    PacketBuffer.Charset charset =
        new PacketBuffer.Charset() {
          @Override
          public String name() {
            return "UTF-8";
          }
        };
    smallBuffer.setCharSequence(0, "Hi", charset);
    mediumBuffer.setCharSequence(0, "Hi", charset);
    largeBuffer.setCharSequence(0, "Hi", charset);
    Assertions.assertEquals("Hi", smallBuffer.getCharSequence(0, SHORT_BYTES, charset));
    Assertions.assertEquals("Hi", mediumBuffer.getCharSequence(0, SHORT_BYTES, charset));
    Assertions.assertEquals("Hi", largeBuffer.getCharSequence(0, SHORT_BYTES, charset));

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void setBoolean() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    for (int i = 0; i < SHORT_BYTES; i++) {
      smallBuffer.setBoolean(i, i % 2 == 0);
      if (i % 2 == 0) {
        Assertions.assertTrue(smallBuffer.getByte(i) == 1);
      } else {
        Assertions.assertTrue(smallBuffer.getByte(i) == 0);
      }
    }
    for (int i = 0; i < INTEGER_BYTES; i++) {
      mediumBuffer.setBoolean(i, i % 2 == 0);
      if (i % 2 == 0) {
        Assertions.assertTrue(mediumBuffer.getByte(i) == 1);
      } else {
        Assertions.assertTrue(mediumBuffer.getByte(i) == 0);
      }
    }
    for (int i = 0; i < LONG_BYTES; i++) {
      largeBuffer.setBoolean(i, i % 2 == 0);
      if (i % 2 == 0) {
        Assertions.assertTrue(largeBuffer.getByte(i) == 1);
      } else {
        Assertions.assertTrue(largeBuffer.getByte(i) == 0);
      }
    }

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void setShortRE() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    for (int i = 0; i < SHORT_BYTES / SHORT_BYTES; i++) {
      smallBuffer.setShortRE(i, i);
      Assertions.assertEquals(Short.reverseBytes((short) i), smallBuffer.getShort(i));
    }
    for (int i = 0; i < INTEGER_BYTES / SHORT_BYTES; i++) {
      mediumBuffer.setShortRE(i, i);
      Assertions.assertEquals(Short.reverseBytes((short) i), mediumBuffer.getShort(i));
    }
    for (int i = 0; i < LONG_BYTES / SHORT_BYTES; i++) {
      largeBuffer.setShortRE(i, i);
      Assertions.assertEquals(Short.reverseBytes((short) i), largeBuffer.getShort(i));
    }

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void setIntRE() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    for (int i = 0; i < INTEGER_BYTES / INTEGER_BYTES; i++) {
      mediumBuffer.setIntRE(i, i);
      Assertions.assertEquals(Integer.reverseBytes(i), mediumBuffer.getInt(i));
    }
    for (int i = 0; i < LONG_BYTES / INTEGER_BYTES; i++) {
      largeBuffer.setIntRE(i, i);
      Assertions.assertEquals(Integer.reverseBytes(i), largeBuffer.getInt(i));
    }

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void setLongRE() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    for (int i = 0; i < LONG_BYTES / LONG_BYTES; i++) {
      largeBuffer.setLongRE(i, 0xFFFFFFFFFFFFFFFFL);
      Assertions.assertEquals(Long.reverseBytes(0xFFFFFFFFFFFFFFFFL), largeBuffer.getLong(i));
    }

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void setFloat() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    for (int i = 0; i < INTEGER_BYTES / INTEGER_BYTES; i++) {
      mediumBuffer.setFloat(i, i + 0.5F);
      Assertions.assertEquals(i + 0.5F, mediumBuffer.getFloat(i));
    }
    for (int i = 0; i < LONG_BYTES / INTEGER_BYTES; i++) {
      largeBuffer.setFloat(i, i + 0.5F);
      Assertions.assertEquals(i + 0.5F, largeBuffer.getFloat(i));
    }

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void setFloatRE() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    for (int i = 0; i < INTEGER_BYTES / INTEGER_BYTES; i++) {
      mediumBuffer.setFloatRE(i, i + 0.5F);
      Assertions.assertEquals(
          Float.intBitsToFloat(mediumBuffer.getIntRE(i)), mediumBuffer.getFloatRE(i));
    }
    for (int i = 0; i < LONG_BYTES / INTEGER_BYTES; i++) {
      largeBuffer.setFloatRE(i, i + 0.5F);
      Assertions.assertEquals(
          Float.intBitsToFloat(largeBuffer.getIntRE(i)), largeBuffer.getFloatRE(i));
    }

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void setDouble() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    for (int i = 0; i < LONG_BYTES / LONG_BYTES; i++) {
      largeBuffer.setDouble(i, i + 0.5D);
      Assertions.assertEquals(i + 0.5D, largeBuffer.getDouble(i));
    }

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void setDoubleRE() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    for (int i = 0; i < LONG_BYTES / LONG_BYTES; i++) {
      largeBuffer.setDoubleRE(i, i + 0.5D);
      Assertions.assertEquals(
          Double.longBitsToDouble(largeBuffer.getLongRE(i)), largeBuffer.getDoubleRE(i));
    }

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void setBytes() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    for (int i = 0; i < SHORT_BYTES; i++) {
      smallBuffer.setByte(i, i);
      Assertions.assertEquals(i, smallBuffer.getByte(i));
    }
    for (int i = 0; i < INTEGER_BYTES; i++) {
      mediumBuffer.setByte(i, i);
      Assertions.assertEquals(i, mediumBuffer.getByte(i));
    }
    smallBuffer.setIndex(0, SHORT_BYTES);
    mediumBuffer.setIndex(0, INTEGER_BYTES);

    largeBuffer.setBytes(0, smallBuffer);
    largeBuffer.setBytes(SHORT_BYTES, mediumBuffer);
    smallBuffer.setIndex(0, SHORT_BYTES);
    largeBuffer.setBytes(INTEGER_BYTES + SHORT_BYTES, smallBuffer);

    Assertions.assertEquals(0, largeBuffer.getByte(0));
    Assertions.assertEquals(1, largeBuffer.getByte(1));
    Assertions.assertEquals(0, largeBuffer.getByte(2));
    Assertions.assertEquals(1, largeBuffer.getByte(3));
    Assertions.assertEquals(2, largeBuffer.getByte(4));
    Assertions.assertEquals(3, largeBuffer.getByte(5));
    Assertions.assertEquals(0, largeBuffer.getByte(6));
    Assertions.assertEquals(1, largeBuffer.getByte(7));

    final byte[] bytes = new byte[LONG_BYTES];
    for (int i = 0; i < bytes.length; i++) {
      bytes[i] = (byte) i;
    }
    largeBuffer.setIndex(0, 0);
    largeBuffer.setBytes(0, bytes, 0, bytes.length);
    for (int i = 0; i < BYTE_BYTES; i++) {
      Assertions.assertEquals(i, largeBuffer.getByte(0));
    }
    largeBuffer.setIndex(0, 0);
    largeBuffer.setBytes(0, bytes);
    for (int i = 0; i < BYTE_BYTES; i++) {
      Assertions.assertEquals(i, largeBuffer.getByte(0));
    }
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setBytes(0, null, SHORT_BYTES);
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setBytes(0, null, INTEGER_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.setIndex(BYTE_BYTES, SHORT_BYTES);
            largeBuffer.setBytes(0, smallBuffer, SHORT_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.setIndex(SHORT_BYTES, INTEGER_BYTES);
            largeBuffer.setBytes(0, smallBuffer, INTEGER_BYTES);
          }
        });

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setBytes(0, smallBuffer, 1, SHORT_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setBytes(0, mediumBuffer, 1, INTEGER_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setBytes(0, bytes, 1, LONG_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setBytes(0, bytes, 1, LONG_BYTES);
          }
        });

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void setCharSequace() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    PacketBuffer.Charset charset =
        new PacketBuffer.Charset() {
          @Override
          public String name() {
            return "UTF-8";
          }
        };
    smallBuffer.setCharSequence(0, "Hi", charset);
    mediumBuffer.setCharSequence(0, "Hi", charset);
    largeBuffer.setCharSequence(0, "Hi", charset);
    Assertions.assertEquals("Hi", smallBuffer.getCharSequence(0, SHORT_BYTES, charset));
    Assertions.assertEquals("Hi", mediumBuffer.getCharSequence(0, SHORT_BYTES, charset));
    Assertions.assertEquals("Hi", largeBuffer.getCharSequence(0, SHORT_BYTES, charset));

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void readBoolean() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    smallBuffer.writeBoolean(true);
    smallBuffer.writeBoolean(false);
    Assertions.assertTrue(smallBuffer.readBoolean());
    Assertions.assertFalse(smallBuffer.readBoolean());
    mediumBuffer.writeBoolean(true);
    mediumBuffer.writeBoolean(false);
    mediumBuffer.writeBoolean(true);
    mediumBuffer.writeBoolean(false);
    Assertions.assertTrue(mediumBuffer.readBoolean());
    Assertions.assertFalse(mediumBuffer.readBoolean());
    Assertions.assertTrue(mediumBuffer.readBoolean());
    Assertions.assertFalse(mediumBuffer.readBoolean());
    largeBuffer.writeBoolean(true);
    largeBuffer.writeBoolean(true);
    largeBuffer.writeBoolean(true);
    largeBuffer.writeBoolean(true);
    largeBuffer.writeBoolean(false);
    largeBuffer.writeBoolean(false);
    largeBuffer.writeBoolean(false);
    largeBuffer.writeBoolean(false);
    Assertions.assertTrue(largeBuffer.readBoolean());
    Assertions.assertTrue(largeBuffer.readBoolean());
    Assertions.assertTrue(largeBuffer.readBoolean());
    Assertions.assertTrue(largeBuffer.readBoolean());
    Assertions.assertFalse(largeBuffer.readBoolean());
    Assertions.assertFalse(largeBuffer.readBoolean());
    Assertions.assertFalse(largeBuffer.readBoolean());
    Assertions.assertFalse(largeBuffer.readBoolean());

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void readByte() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.readByte();
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.readByte();
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.readByte();
          }
        });
    for (int i = 0; i < SHORT_BYTES; i++) {
      smallBuffer.writeByte(i);
      Assertions.assertEquals(i, smallBuffer.readByte());
    }
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.readByte();
          }
        });
    for (int i = 0; i < INTEGER_BYTES; i++) {
      mediumBuffer.writeByte(i);
      Assertions.assertEquals(i, mediumBuffer.readByte());
    }
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.readByte();
          }
        });
    for (int i = 0; i < LONG_BYTES; i++) {
      largeBuffer.writeByte(i);
      Assertions.assertEquals(i, largeBuffer.readByte());
    }
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.readByte();
          }
        });

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void readUnsignedByte() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    for (int i = 0; i < SHORT_BYTES; i++) {
      smallBuffer.writeByte(i);
      Assertions.assertEquals(i, smallBuffer.readUnsignedByte());
    }
    for (int i = 0; i < INTEGER_BYTES; i++) {
      mediumBuffer.writeByte(i);
      Assertions.assertEquals(i, mediumBuffer.readUnsignedByte());
    }
    for (int i = 0; i < LONG_BYTES; i++) {
      largeBuffer.writeByte(i);
      Assertions.assertEquals(i, largeBuffer.readUnsignedByte());
    }

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void readShort() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.readShort();
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.readShort();
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.readShort();
          }
        });
    for (int i = 0; i < SHORT_BYTES / SHORT_BYTES; i++) {
      smallBuffer.writeShort(i);
      Assertions.assertEquals(i, smallBuffer.readShort());
    }
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.readShort();
          }
        });
    for (int i = 0; i < INTEGER_BYTES / SHORT_BYTES; i++) {
      mediumBuffer.writeShort(i);
      Assertions.assertEquals(i, mediumBuffer.readShort());
    }
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.readShort();
          }
        });
    for (int i = 0; i < LONG_BYTES / SHORT_BYTES; i++) {
      largeBuffer.writeShort(i);
      Assertions.assertEquals(i, largeBuffer.readShort());
    }
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.readShort();
          }
        });

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void readShortRE() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.readShortRE();
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.readShortRE();
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.readShortRE();
          }
        });
    for (int i = 0; i < SHORT_BYTES / SHORT_BYTES; i++) {
      smallBuffer.writeShortRE(i);
      Assertions.assertEquals(i, smallBuffer.readShortRE());
    }
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.readShortRE();
          }
        });
    for (int i = 0; i < INTEGER_BYTES / SHORT_BYTES; i++) {
      mediumBuffer.writeShortRE(i);
      Assertions.assertEquals(i, mediumBuffer.readShortRE());
    }
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.readShortRE();
          }
        });
    for (int i = 0; i < LONG_BYTES / SHORT_BYTES; i++) {
      largeBuffer.writeShortRE(i);
      Assertions.assertEquals(i, largeBuffer.readShortRE());
    }
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.readShortRE();
          }
        });

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void readUnsignedShort() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    for (int i = 0; i < SHORT_BYTES / SHORT_BYTES; i++) {
      smallBuffer.writeShort(0xFFFF);
      Assertions.assertEquals(0xFFFF, smallBuffer.readUnsignedShort());
    }
    for (int i = 0; i < INTEGER_BYTES / SHORT_BYTES; i++) {
      mediumBuffer.writeShort(0xFFFF);
      Assertions.assertEquals(0xFFFF, mediumBuffer.readUnsignedShort());
    }
    for (int i = 0; i < LONG_BYTES / SHORT_BYTES; i++) {
      largeBuffer.writeShort(0xFFFF);
      Assertions.assertEquals(0xFFFF, largeBuffer.readUnsignedShort());
    }

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void readUnsignedShortRE() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    for (int i = 0; i < SHORT_BYTES / SHORT_BYTES; i++) {
      smallBuffer.writeShortRE(0xFFFF);
      Assertions.assertEquals(0xFFFF, smallBuffer.readUnsignedShortRE());
    }
    for (int i = 0; i < INTEGER_BYTES / SHORT_BYTES; i++) {
      mediumBuffer.writeShortRE(0xFFFF);
      Assertions.assertEquals(0xFFFF, mediumBuffer.readUnsignedShortRE());
    }
    for (int i = 0; i < LONG_BYTES / SHORT_BYTES; i++) {
      largeBuffer.writeShortRE(0xFFFF);
      Assertions.assertEquals(0xFFFF, largeBuffer.readUnsignedShortRE());
    }

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void readInt() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.readInt();
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.readInt();
          }
        });
    for (int i = 0; i < INTEGER_BYTES / INTEGER_BYTES; i++) {
      mediumBuffer.writeInt(i);
      Assertions.assertEquals(i, mediumBuffer.readInt());
    }
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.readInt();
          }
        });
    for (int i = 0; i < LONG_BYTES / INTEGER_BYTES; i++) {
      largeBuffer.writeInt(i);
      Assertions.assertEquals(i, largeBuffer.readInt());
    }
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.readInt();
          }
        });

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void readIntRE() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.readIntRE();
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.readIntRE();
          }
        });
    for (int i = 0; i < INTEGER_BYTES / INTEGER_BYTES; i++) {
      mediumBuffer.writeIntRE(i);
      Assertions.assertEquals(i, mediumBuffer.readIntRE());
    }
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.readIntRE();
          }
        });
    for (int i = 0; i < LONG_BYTES / INTEGER_BYTES; i++) {
      largeBuffer.writeIntRE(i);
      Assertions.assertEquals(i, largeBuffer.readIntRE());
    }
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.readIntRE();
          }
        });

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void readUnsignedInt() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    for (int i = 0; i < INTEGER_BYTES / INTEGER_BYTES; i++) {
      mediumBuffer.writeInt(0xFFFFFFFF);
      Assertions.assertEquals(0xFFFFFFFFL, mediumBuffer.readUnsignedInt());
    }
    for (int i = 0; i < LONG_BYTES / INTEGER_BYTES; i++) {
      largeBuffer.writeInt(0xFFFFFFFF);
      Assertions.assertEquals(0xFFFFFFFFL, largeBuffer.readUnsignedInt());
    }

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void readUnsignedIntRE() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    for (int i = 0; i < INTEGER_BYTES / INTEGER_BYTES; i++) {
      mediumBuffer.writeIntRE(0xFFFFFFFF);
      Assertions.assertEquals(0xFFFFFFFFL, mediumBuffer.readUnsignedIntRE());
    }
    for (int i = 0; i < LONG_BYTES / INTEGER_BYTES; i++) {
      largeBuffer.writeIntRE(0xFFFFFFFF);
      Assertions.assertEquals(0xFFFFFFFFL, largeBuffer.readUnsignedIntRE());
    }

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void readFloat() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    for (int i = 0; i < INTEGER_BYTES / INTEGER_BYTES; i++) {
      mediumBuffer.writeFloat(i + 0.5F);
      Assertions.assertEquals(i + 0.5F, mediumBuffer.readFloat());
    }
    for (int i = 0; i < LONG_BYTES / INTEGER_BYTES; i++) {
      largeBuffer.writeFloat(i + 0.5F);
      Assertions.assertEquals(i + 0.5F, largeBuffer.readFloat());
    }

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void readFloatRE() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    for (int i = 0; i < INTEGER_BYTES / INTEGER_BYTES; i++) {
      mediumBuffer.writeFloatRE(i + 0.5F);
      Assertions.assertEquals(i + 0.5F, mediumBuffer.readFloatRE());
    }
    for (int i = 0; i < LONG_BYTES / INTEGER_BYTES; i++) {
      largeBuffer.writeFloatRE(i + 0.5F);
      Assertions.assertEquals(i + 0.5F, largeBuffer.readFloatRE());
    }

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void readDouble() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    for (int i = 0; i < LONG_BYTES / LONG_BYTES; i++) {
      largeBuffer.writeDouble(i + 0.5D);
      Assertions.assertEquals(i + 0.5D, largeBuffer.readDouble());
    }

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void readDoubleRE() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    for (int i = 0; i < LONG_BYTES / LONG_BYTES; i++) {
      largeBuffer.writeDoubleRE(i + 0.5D);
      Assertions.assertEquals(i + 0.5D, largeBuffer.readDoubleRE());
    }

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void readLong() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.readLong();
          }
        });
    largeBuffer.writeLong(Long.MAX_VALUE);
    Assertions.assertEquals(Long.MAX_VALUE, largeBuffer.readLong());
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.readLong();
          }
        });

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void readLongRE() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.readLongRE();
          }
        });
    largeBuffer.writeLongRE(Long.MAX_VALUE);
    Assertions.assertEquals(Long.MAX_VALUE, largeBuffer.readLongRE());
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.readLongRE();
          }
        });

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void readBytes() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    final byte[] smallBytesDst = new byte[SHORT_BYTES];
    final DefaultPacketBuffer smallBufDst =
        DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final byte[] mediumBytesDst = new byte[INTEGER_BYTES];
    final DefaultPacketBuffer mediumBufDst =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final byte[] largeBytesDst = new byte[LONG_BYTES];
    final DefaultPacketBuffer largeBufDst =
        DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    for (int i = 0; i < SHORT_BYTES; i++) {
      smallBuffer.writeByte(i);
    }
    for (int i = 0; i < INTEGER_BYTES; i++) {
      mediumBuffer.writeByte(i);
    }
    for (int i = 0; i < LONG_BYTES; i++) {
      largeBuffer.writeByte(i);
    }
    // PacketBuffer readBytes(PacketBuffer dst)
    Assertions.assertEquals(smallBuffer.writerIndex(), SHORT_BYTES);
    smallBuffer.readBytes(smallBufDst);
    smallBuffer.setIndex(0, SHORT_BYTES);
    smallBufDst.setIndex(0, SHORT_BYTES);
    for (int i = 0; i < SHORT_BYTES; i++) {
      Assertions.assertEquals(smallBuffer.readByte(), smallBufDst.readByte());
    }
    Assertions.assertEquals(mediumBuffer.writerIndex(), INTEGER_BYTES);
    mediumBuffer.readBytes(mediumBufDst);
    mediumBuffer.setIndex(0, INTEGER_BYTES);
    mediumBufDst.setIndex(0, INTEGER_BYTES);
    for (int i = 0; i < INTEGER_BYTES; i++) {
      Assertions.assertEquals(mediumBuffer.readByte(), mediumBufDst.readByte());
    }
    Assertions.assertEquals(largeBuffer.writerIndex(), LONG_BYTES);
    largeBuffer.readBytes(largeBufDst);
    largeBuffer.setIndex(0, LONG_BYTES);
    largeBufDst.setIndex(0, LONG_BYTES);
    for (int i = 0; i < LONG_BYTES; i++) {
      Assertions.assertEquals(largeBuffer.readByte(), largeBufDst.readByte());
    }

    smallBuffer.setIndex(0, SHORT_BYTES);
    smallBufDst.setIndex(0, 0);
    mediumBuffer.setIndex(0, INTEGER_BYTES);
    mediumBufDst.setIndex(0, 0);
    largeBuffer.setIndex(0, LONG_BYTES);
    largeBufDst.setIndex(0, 0);

    // PacketBuffer readBytes(PacketBuffer dst, long length)
    Assertions.assertEquals(smallBuffer.writerIndex(), SHORT_BYTES);
    smallBuffer.readBytes(smallBufDst, SHORT_BYTES);
    smallBuffer.setIndex(0, SHORT_BYTES);
    smallBufDst.setIndex(0, SHORT_BYTES);
    for (int i = 0; i < SHORT_BYTES; i++) {
      Assertions.assertEquals(smallBuffer.readByte(), smallBufDst.readByte());
    }
    Assertions.assertEquals(mediumBuffer.writerIndex(), INTEGER_BYTES);
    mediumBuffer.readBytes(mediumBufDst, INTEGER_BYTES);
    mediumBuffer.setIndex(0, INTEGER_BYTES);
    mediumBufDst.setIndex(0, INTEGER_BYTES);
    for (int i = 0; i < INTEGER_BYTES; i++) {
      Assertions.assertEquals(mediumBuffer.readByte(), mediumBufDst.readByte());
    }
    Assertions.assertEquals(largeBuffer.writerIndex(), LONG_BYTES);
    largeBuffer.readBytes(largeBufDst, LONG_BYTES);
    largeBuffer.setIndex(0, LONG_BYTES);
    largeBufDst.setIndex(0, LONG_BYTES);
    for (int i = 0; i < LONG_BYTES; i++) {
      Assertions.assertEquals(largeBuffer.readByte(), largeBufDst.readByte());
    }

    smallBuffer.setIndex(BYTE_BYTES, SHORT_BYTES);
    smallBufDst.setIndex(BYTE_BYTES, SHORT_BYTES);
    mediumBuffer.setIndex(BYTE_BYTES, INTEGER_BYTES);
    mediumBufDst.setIndex(BYTE_BYTES, INTEGER_BYTES);
    largeBuffer.setIndex(BYTE_BYTES, LONG_BYTES);
    largeBufDst.setIndex(BYTE_BYTES, LONG_BYTES);

    // PacketBuffer readBytes(PacketBuffer dst, long dstIndex, long length)
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.readBytes(smallBufDst, -1);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.readBytes(smallBufDst, SHORT_BYTES);
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.readBytes(mediumBufDst, -1);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.readBytes(mediumBufDst, INTEGER_BYTES);
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.readBytes(largeBufDst, -1);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.readBytes(largeBufDst, LONG_BYTES);
          }
        });

    // PacketBuffer readBytes(byte[] dst)
    smallBuffer.setIndex(0, SHORT_BYTES);
    smallBufDst.setIndex(0, 0);
    mediumBuffer.setIndex(0, INTEGER_BYTES);
    mediumBufDst.setIndex(0, 0);
    largeBuffer.setIndex(0, LONG_BYTES);
    largeBufDst.setIndex(0, 0);

    smallBuffer.readBytes(smallBytesDst);
    for (int i = 0; i < SHORT_BYTES; i++) {
      Assertions.assertEquals(smallBuffer.getByte(i), smallBytesDst[i]);
    }
    mediumBuffer.readBytes(mediumBytesDst);
    for (int i = 0; i < INTEGER_BYTES; i++) {
      Assertions.assertEquals(mediumBuffer.getByte(i), mediumBytesDst[i]);
    }
    largeBuffer.readBytes(largeBytesDst);
    for (int i = 0; i < LONG_BYTES; i++) {
      Assertions.assertEquals(largeBuffer.getByte(i), largeBytesDst[i]);
    }

    // PacketBuffer readBytes(byte[] dst, long dstIndex, long length)
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.readBytes(smallBytesDst, 0, -1);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.readBytes(smallBytesDst, BYTE_BYTES, SHORT_BYTES);
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.readBytes(mediumBytesDst, 0, -1);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.readBytes(mediumBytesDst, BYTE_BYTES, INTEGER_BYTES);
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.readBytes(largeBytesDst, 0, -1);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.readBytes(largeBytesDst, BYTE_BYTES, LONG_BYTES);
          }
        });
    Assertions.assertTrue(smallBufDst.release());
    Assertions.assertTrue(mediumBufDst.release());
    Assertions.assertTrue(largeBufDst.release());

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void skipBytes() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    for (int i = 0; i < LONG_BYTES; i++) {
      largeBuffer.writeByte(i);
    }
    largeBuffer.skipBytes(1);
    Assertions.assertEquals(1, largeBuffer.readByte());
    largeBuffer.skipBytes(2);
    Assertions.assertEquals(4, largeBuffer.readByte());
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.skipBytes(4);
          }
        });

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void readCharSequence() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    PacketBuffer.Charset charset =
        new PacketBuffer.Charset() {
          @Override
          public String name() {
            return "UTF-8";
          }
        };
    smallBuffer.writeCharSequence("Hi", charset);
    mediumBuffer.writeCharSequence("Hi", charset);
    largeBuffer.writeCharSequence("Hi", charset);
    Assertions.assertEquals("Hi", smallBuffer.readCharSequence(SHORT_BYTES, charset));
    Assertions.assertEquals("Hi", mediumBuffer.readCharSequence(SHORT_BYTES, charset));
    Assertions.assertEquals("Hi", largeBuffer.readCharSequence(SHORT_BYTES, charset));

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void writeBoolean() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    smallBuffer.writeBoolean(true);
    smallBuffer.writeBoolean(false);
    Assertions.assertTrue(smallBuffer.readBoolean());
    Assertions.assertFalse(smallBuffer.readBoolean());
    mediumBuffer.writeBoolean(true);
    mediumBuffer.writeBoolean(false);
    mediumBuffer.writeBoolean(true);
    mediumBuffer.writeBoolean(false);
    Assertions.assertTrue(mediumBuffer.readBoolean());
    Assertions.assertFalse(mediumBuffer.readBoolean());
    Assertions.assertTrue(mediumBuffer.readBoolean());
    Assertions.assertFalse(mediumBuffer.readBoolean());
    largeBuffer.writeBoolean(true);
    largeBuffer.writeBoolean(true);
    largeBuffer.writeBoolean(true);
    largeBuffer.writeBoolean(true);
    largeBuffer.writeBoolean(false);
    largeBuffer.writeBoolean(false);
    largeBuffer.writeBoolean(false);
    largeBuffer.writeBoolean(false);
    Assertions.assertTrue(largeBuffer.readBoolean());
    Assertions.assertTrue(largeBuffer.readBoolean());
    Assertions.assertTrue(largeBuffer.readBoolean());
    Assertions.assertTrue(largeBuffer.readBoolean());
    Assertions.assertFalse(largeBuffer.readBoolean());
    Assertions.assertFalse(largeBuffer.readBoolean());
    Assertions.assertFalse(largeBuffer.readBoolean());
    Assertions.assertFalse(largeBuffer.readBoolean());

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void writeByte() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.setIndex(0, SHORT_BYTES).writeByte(BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.setIndex(0, INTEGER_BYTES).writeByte(BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setIndex(0, LONG_BYTES).writeByte(BYTE_BYTES);
          }
        });

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void writeShort() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.setIndex(0, SHORT_BYTES).writeShort(BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.setIndex(0, INTEGER_BYTES).writeShort(BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setIndex(0, LONG_BYTES).writeShort(BYTE_BYTES);
          }
        });

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void writeShortRE() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.setIndex(0, SHORT_BYTES).writeShortRE(BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.setIndex(0, INTEGER_BYTES).writeShortRE(BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setIndex(0, LONG_BYTES).writeShortRE(BYTE_BYTES);
          }
        });

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void writeInt() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.setIndex(0, INTEGER_BYTES).writeInt(BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setIndex(0, LONG_BYTES).writeInt(BYTE_BYTES);
          }
        });

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void writeIntRE() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.setIndex(0, INTEGER_BYTES).writeIntRE(BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setIndex(0, LONG_BYTES).writeIntRE(BYTE_BYTES);
          }
        });

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void writeLong() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setIndex(0, LONG_BYTES).writeLong(BYTE_BYTES);
          }
        });

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void writeLongRE() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setIndex(0, LONG_BYTES).writeLongRE(BYTE_BYTES);
          }
        });

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void writeFloat() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.setIndex(0, INTEGER_BYTES).writeFloat(BYTE_BYTES + 0.5F);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setIndex(0, LONG_BYTES).writeFloat(BYTE_BYTES + 0.5F);
          }
        });

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void writeFloatRE() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.setIndex(0, INTEGER_BYTES).writeFloatRE(BYTE_BYTES + 0.5F);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setIndex(0, LONG_BYTES).writeFloatRE(BYTE_BYTES + 0.5F);
          }
        });

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void writeDouble() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setIndex(0, LONG_BYTES).writeDouble(BYTE_BYTES + 0.5D);
          }
        });

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void writeDoubleRE() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setIndex(0, LONG_BYTES).writeDoubleRE(BYTE_BYTES + 0.5D);
          }
        });

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void writeBytes() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    final byte[] smallBytesDst = new byte[SHORT_BYTES];
    final DefaultPacketBuffer smallBufSrc =
        DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final byte[] mediumBytesDst = new byte[INTEGER_BYTES];
    final DefaultPacketBuffer mediumBufSrc =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final byte[] largeBytesDst = new byte[LONG_BYTES];
    final DefaultPacketBuffer largeBufSrc =
        DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    for (int i = 0; i < SHORT_BYTES; i++) {
      smallBufSrc.writeByte(i);
    }
    for (int i = 0; i < INTEGER_BYTES; i++) {
      mediumBufSrc.writeByte(i);
    }
    for (int i = 0; i < LONG_BYTES; i++) {
      largeBufSrc.writeByte(i);
    }
    // PacketBuffer readBytes(PacketBuffer dst)
    Assertions.assertEquals(smallBufSrc.writerIndex(), SHORT_BYTES);
    smallBuffer.writeBytes(smallBufSrc);
    smallBuffer.setIndex(0, SHORT_BYTES);
    smallBufSrc.setIndex(0, SHORT_BYTES);
    for (int i = 0; i < SHORT_BYTES; i++) {
      Assertions.assertEquals(smallBuffer.readByte(), smallBufSrc.readByte());
    }
    Assertions.assertEquals(mediumBufSrc.writerIndex(), INTEGER_BYTES);
    mediumBuffer.writeBytes(mediumBufSrc);
    mediumBuffer.setIndex(0, INTEGER_BYTES);
    mediumBufSrc.setIndex(0, INTEGER_BYTES);
    for (int i = 0; i < INTEGER_BYTES; i++) {
      Assertions.assertEquals(mediumBuffer.readByte(), mediumBufSrc.readByte());
    }
    Assertions.assertEquals(largeBufSrc.writerIndex(), LONG_BYTES);
    largeBuffer.writeBytes(largeBufSrc);
    largeBuffer.setIndex(0, LONG_BYTES);
    largeBufSrc.setIndex(0, LONG_BYTES);
    for (int i = 0; i < LONG_BYTES; i++) {
      Assertions.assertEquals(largeBuffer.readByte(), largeBufSrc.readByte());
    }

    smallBufSrc.setIndex(0, SHORT_BYTES);
    smallBuffer.setIndex(0, 0);
    mediumBufSrc.setIndex(0, INTEGER_BYTES);
    mediumBuffer.setIndex(0, 0);
    largeBufSrc.setIndex(0, LONG_BYTES);
    largeBuffer.setIndex(0, 0);

    // PacketBuffer readBytes(PacketBuffer dst, long length)
    Assertions.assertEquals(smallBufSrc.writerIndex(), SHORT_BYTES);
    smallBuffer.writeBytes(smallBufSrc, SHORT_BYTES);
    smallBuffer.setIndex(0, SHORT_BYTES);
    smallBufSrc.setIndex(0, SHORT_BYTES);
    for (int i = 0; i < SHORT_BYTES; i++) {
      Assertions.assertEquals(smallBuffer.readByte(), smallBufSrc.readByte());
    }
    Assertions.assertEquals(mediumBufSrc.writerIndex(), INTEGER_BYTES);
    mediumBuffer.writeBytes(mediumBufSrc, INTEGER_BYTES);
    mediumBuffer.setIndex(0, INTEGER_BYTES);
    mediumBufSrc.setIndex(0, INTEGER_BYTES);
    for (int i = 0; i < INTEGER_BYTES; i++) {
      Assertions.assertEquals(mediumBuffer.readByte(), mediumBufSrc.readByte());
    }
    Assertions.assertEquals(largeBufSrc.writerIndex(), LONG_BYTES);
    largeBuffer.writeBytes(largeBufSrc, LONG_BYTES);
    largeBuffer.setIndex(0, LONG_BYTES);
    largeBufSrc.setIndex(0, LONG_BYTES);
    for (int i = 0; i < LONG_BYTES; i++) {
      Assertions.assertEquals(largeBuffer.readByte(), largeBufSrc.readByte());
    }

    smallBuffer.setIndex(BYTE_BYTES, SHORT_BYTES);
    smallBufSrc.setIndex(BYTE_BYTES, SHORT_BYTES);
    mediumBuffer.setIndex(BYTE_BYTES, INTEGER_BYTES);
    mediumBufSrc.setIndex(BYTE_BYTES, INTEGER_BYTES);
    largeBuffer.setIndex(BYTE_BYTES, LONG_BYTES);
    largeBufSrc.setIndex(BYTE_BYTES, LONG_BYTES);

    // PacketBuffer writeBytes(PacketBuffer dst, long dstIndex, long length)
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.writeBytes(smallBufSrc, -1);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.writeBytes(smallBufSrc, SHORT_BYTES);
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.readBytes(mediumBufSrc, -1);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.writeBytes(mediumBufSrc, INTEGER_BYTES);
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.writeBytes(largeBufSrc, -1);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.writeBytes(largeBufSrc, LONG_BYTES);
          }
        });

    // PacketBuffer writeBytes(byte[] dst)
    smallBuffer.setIndex(0, SHORT_BYTES);
    smallBufSrc.setIndex(0, 0);
    mediumBuffer.setIndex(0, INTEGER_BYTES);
    mediumBufSrc.setIndex(0, 0);
    largeBuffer.setIndex(0, LONG_BYTES);
    largeBufSrc.setIndex(0, 0);

    smallBuffer.readBytes(smallBytesDst);
    for (int i = 0; i < SHORT_BYTES; i++) {
      Assertions.assertEquals(smallBuffer.getByte(i), smallBytesDst[i]);
    }
    mediumBuffer.readBytes(mediumBytesDst);
    for (int i = 0; i < INTEGER_BYTES; i++) {
      Assertions.assertEquals(mediumBuffer.getByte(i), mediumBytesDst[i]);
    }
    largeBuffer.readBytes(largeBytesDst);
    for (int i = 0; i < LONG_BYTES; i++) {
      Assertions.assertEquals(largeBuffer.getByte(i), largeBytesDst[i]);
    }

    // PacketBuffer writeBytes(byte[] dst, long dstIndex, long length)
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.readBytes(smallBytesDst, 0, -1);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.readBytes(smallBytesDst, BYTE_BYTES, SHORT_BYTES);
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.readBytes(mediumBytesDst, 0, -1);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.readBytes(mediumBytesDst, BYTE_BYTES, INTEGER_BYTES);
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.readBytes(largeBytesDst, 0, -1);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.readBytes(largeBytesDst, BYTE_BYTES, LONG_BYTES);
          }
        });

    Assertions.assertTrue(smallBufSrc.release());
    Assertions.assertTrue(mediumBufSrc.release());
    Assertions.assertTrue(largeBufSrc.release());

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void writeCharSequence() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    PacketBuffer.Charset charset =
        new PacketBuffer.Charset() {
          @Override
          public String name() {
            return "UTF-8";
          }
        };
    smallBuffer.writeCharSequence("Hi", charset);
    mediumBuffer.writeCharSequence("Hi", charset);
    largeBuffer.writeCharSequence("Hi", charset);
    Assertions.assertEquals("Hi", smallBuffer.readCharSequence(SHORT_BYTES, charset));
    Assertions.assertEquals("Hi", mediumBuffer.readCharSequence(SHORT_BYTES, charset));
    Assertions.assertEquals("Hi", largeBuffer.readCharSequence(SHORT_BYTES, charset));

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void byteOrder() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    Assertions.assertEquals(PacketBuffer.ByteOrder.NATIVE, smallBuffer.byteOrder());
    Assertions.assertEquals(PacketBuffer.ByteOrder.NATIVE, mediumBuffer.byteOrder());
    Assertions.assertEquals(PacketBuffer.ByteOrder.NATIVE, largeBuffer.byteOrder());

    Assertions.assertEquals(
        PacketBuffer.ByteOrder.BIG_ENDIAN,
        smallBuffer.byteOrder(PacketBuffer.ByteOrder.BIG_ENDIAN).byteOrder());
    Assertions.assertEquals(
        PacketBuffer.ByteOrder.BIG_ENDIAN,
        mediumBuffer.byteOrder(PacketBuffer.ByteOrder.BIG_ENDIAN).byteOrder());
    Assertions.assertEquals(
        PacketBuffer.ByteOrder.BIG_ENDIAN,
        largeBuffer.byteOrder(PacketBuffer.ByteOrder.BIG_ENDIAN).byteOrder());

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void copy() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    for (int i = 0; i < SHORT_BYTES; i++) {
      smallBuffer.writeByte(i);
    }
    for (int i = 0; i < INTEGER_BYTES; i++) {
      mediumBuffer.writeByte(i);
    }
    for (int i = 0; i < LONG_BYTES; i++) {
      largeBuffer.writeByte(i);
    }
    PacketBuffer smallCopy = smallBuffer.copy();
    PacketBuffer smallCopySliced = smallBuffer.copy(BYTE_BYTES, BYTE_BYTES);
    PacketBuffer mediumCopy = mediumBuffer.copy();
    PacketBuffer mediumCopySliced = mediumBuffer.copy(SHORT_BYTES, SHORT_BYTES);
    PacketBuffer largeCopy = largeBuffer.copy();
    PacketBuffer largeCopySliced = largeBuffer.copy(INTEGER_BYTES, INTEGER_BYTES);

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.copy(-BYTE_BYTES, BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.copy(BYTE_BYTES, LONG_BYTES + BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.copy(-BYTE_BYTES, BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.copy(BYTE_BYTES, LONG_BYTES + BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.copy(-BYTE_BYTES, BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.copy(BYTE_BYTES, LONG_BYTES + BYTE_BYTES);
          }
        });

    for (int i = 0; i < SHORT_BYTES; i++) {
      Assertions.assertEquals(smallCopy.getByte(i), smallBuffer.getByte(i));
    }
    for (int i = BYTE_BYTES; i < BYTE_BYTES + BYTE_BYTES; i++) {
      Assertions.assertEquals(smallCopySliced.getByte(i - BYTE_BYTES), smallBuffer.getByte(i));
    }
    for (int i = 0; i < INTEGER_BYTES; i++) {
      Assertions.assertEquals(mediumCopy.getByte(i), mediumBuffer.getByte(i));
    }
    for (int i = SHORT_BYTES; i < SHORT_BYTES + SHORT_BYTES; i++) {
      Assertions.assertEquals(mediumCopySliced.getByte(i - SHORT_BYTES), mediumBuffer.getByte(i));
    }
    for (int i = 0; i < LONG_BYTES; i++) {
      Assertions.assertEquals(largeCopy.getByte(i), largeBuffer.getByte(i));
    }
    for (int i = INTEGER_BYTES; i < INTEGER_BYTES + INTEGER_BYTES; i++) {
      Assertions.assertEquals(largeCopySliced.getByte(i - INTEGER_BYTES), largeBuffer.getByte(i));
    }

    Assertions.assertTrue(smallCopy.release());
    Assertions.assertTrue(smallCopySliced.release());
    Assertions.assertTrue(mediumCopy.release());
    Assertions.assertTrue(mediumCopySliced.release());
    Assertions.assertTrue(largeCopy.release());
    Assertions.assertTrue(largeCopySliced.release());

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void slice() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    Assertions.assertEquals(0, smallBuffer.slice().capacity());
    Assertions.assertEquals(1, smallBuffer.writerIndex(BYTE_BYTES).slice().capacity());
    Assertions.assertEquals(0, mediumBuffer.slice().capacity());
    Assertions.assertEquals(1, mediumBuffer.writerIndex(BYTE_BYTES).slice().capacity());
    Assertions.assertEquals(0, largeBuffer.slice().capacity());
    Assertions.assertEquals(1, largeBuffer.writerIndex(BYTE_BYTES).slice().capacity());

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.writerIndex(SHORT_BYTES).slice(-BYTE_BYTES, SHORT_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.writerIndex(SHORT_BYTES).slice(0, SHORT_BYTES + BYTE_BYTES);
          }
        });

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.writerIndex(INTEGER_BYTES).slice(-BYTE_BYTES, INTEGER_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.writerIndex(INTEGER_BYTES).slice(0, INTEGER_BYTES + BYTE_BYTES);
          }
        });

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.writerIndex(LONG_BYTES).slice(-BYTE_BYTES, LONG_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.writerIndex(LONG_BYTES).slice(0, LONG_BYTES + BYTE_BYTES);
          }
        });

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void getByte() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.getByte(-BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.getByte(SHORT_BYTES + BYTE_BYTES);
          }
        });

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.getByte(-BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.getByte(INTEGER_BYTES + BYTE_BYTES);
          }
        });

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.getByte(-BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.getByte(LONG_BYTES + BYTE_BYTES);
          }
        });

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void getShort() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.getShort(-BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.getShort(SHORT_BYTES + BYTE_BYTES);
          }
        });

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.getShort(-BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.getShort(INTEGER_BYTES + BYTE_BYTES);
          }
        });

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.getShort(-BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.getShort(LONG_BYTES + BYTE_BYTES);
          }
        });

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void getInt() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.getInt(-BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.getInt(INTEGER_BYTES + BYTE_BYTES);
          }
        });

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.getInt(-BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.getInt(LONG_BYTES + BYTE_BYTES);
          }
        });

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void getLong() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.getLong(-BYTE_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.getLong(LONG_BYTES + BYTE_BYTES);
          }
        });

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void setByte() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.setByte(-BYTE_BYTES, SHORT_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.setByte(SHORT_BYTES + BYTE_BYTES, SHORT_BYTES);
          }
        });

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.setByte(-BYTE_BYTES, INTEGER_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.setByte(INTEGER_BYTES + BYTE_BYTES, INTEGER_BYTES);
          }
        });

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setByte(-BYTE_BYTES, LONG_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setByte(LONG_BYTES + BYTE_BYTES, LONG_BYTES);
          }
        });

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void setShort() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.setShort(-BYTE_BYTES, SHORT_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.setShort(SHORT_BYTES + BYTE_BYTES, SHORT_BYTES);
          }
        });

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.setShort(-BYTE_BYTES, INTEGER_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.setShort(INTEGER_BYTES + BYTE_BYTES, INTEGER_BYTES);
          }
        });

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setShort(-BYTE_BYTES, LONG_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setShort(LONG_BYTES + BYTE_BYTES, LONG_BYTES);
          }
        });

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void setInt() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.setInt(-BYTE_BYTES, INTEGER_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.setInt(INTEGER_BYTES + BYTE_BYTES, INTEGER_BYTES);
          }
        });

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setInt(-BYTE_BYTES, LONG_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setInt(LONG_BYTES + BYTE_BYTES, LONG_BYTES);
          }
        });

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void setLong() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setLong(-BYTE_BYTES, LONG_BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setLong(LONG_BYTES + BYTE_BYTES, LONG_BYTES);
          }
        });

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void duplicate() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    Assertions.assertEquals(smallBuffer.capacity(), smallBuffer.duplicate().capacity());
    Assertions.assertEquals(mediumBuffer.capacity(), mediumBuffer.duplicate().capacity());
    Assertions.assertEquals(largeBuffer.capacity(), largeBuffer.duplicate().capacity());
    Assertions.assertEquals(smallBuffer.writerIndex(), smallBuffer.duplicate().writerIndex());
    Assertions.assertEquals(mediumBuffer.writerIndex(), mediumBuffer.duplicate().writerIndex());
    Assertions.assertEquals(largeBuffer.writerIndex(), largeBuffer.duplicate().writerIndex());
    Assertions.assertEquals(smallBuffer.readerIndex(), smallBuffer.duplicate().readerIndex());
    Assertions.assertEquals(mediumBuffer.readerIndex(), mediumBuffer.duplicate().readerIndex());
    Assertions.assertEquals(largeBuffer.readerIndex(), largeBuffer.duplicate().readerIndex());

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void unSlice() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    PacketBuffer smallSlice = smallBuffer.slice(BYTE_BYTES, BYTE_BYTES);
    PacketBuffer mediumSlice = mediumBuffer.slice(BYTE_BYTES, SHORT_BYTES);
    PacketBuffer largeSlice = largeBuffer.slice(BYTE_BYTES, INTEGER_BYTES);
    Assertions.assertEquals(smallBuffer, ((PacketBuffer.Sliced) smallSlice).unSlice());
    Assertions.assertEquals(mediumBuffer, ((PacketBuffer.Sliced) mediumSlice).unSlice());
    Assertions.assertEquals(largeBuffer, ((PacketBuffer.Sliced) largeSlice).unSlice());

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  public void slicedRelease() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer slicedSmallBuffer = smallBuffer.slice();
    Assertions.assertTrue(slicedSmallBuffer.release());
    Assertions.assertFalse(smallBuffer.release());

    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer slicedMediumBuffer = mediumBuffer.slice();
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertFalse(slicedMediumBuffer.release());
  }

  @Test
  void clear() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    smallBuffer.setIndex(BYTE_BYTES, BYTE_BYTES);
    mediumBuffer.setIndex(BYTE_BYTES, BYTE_BYTES);
    largeBuffer.setIndex(BYTE_BYTES, BYTE_BYTES);
    smallBuffer.clear();
    mediumBuffer.clear();
    largeBuffer.clear();
    Assertions.assertEquals(0, smallBuffer.readerIndex());
    Assertions.assertEquals(0, smallBuffer.writerIndex());
    Assertions.assertEquals(0, mediumBuffer.readerIndex());
    Assertions.assertEquals(0, mediumBuffer.writerIndex());
    Assertions.assertEquals(0, largeBuffer.readerIndex());
    Assertions.assertEquals(0, largeBuffer.writerIndex());

    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }

  @Test
  void release() {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    Assertions.assertTrue(smallBuffer.slice().release());
    Assertions.assertTrue(mediumBuffer.slice().release());
    Assertions.assertTrue(largeBuffer.slice().release());
    Assertions.assertFalse(new DefaultPacketBuffer().release());

    Assertions.assertFalse(smallBuffer.release());
    Assertions.assertFalse(mediumBuffer.release());
    Assertions.assertFalse(largeBuffer.release());
  }

  @Test
  void autoCloseable() throws Exception {
    final PacketBuffer smallBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(SHORT_BYTES);
    final PacketBuffer mediumBuffer =
        DefaultPacketBuffer.PacketBufferManager.allocate(INTEGER_BYTES);
    final PacketBuffer largeBuffer = DefaultPacketBuffer.PacketBufferManager.allocate(LONG_BYTES);

    smallBuffer.slice().close();
    mediumBuffer.slice().close();
    largeBuffer.slice().close();
    try (PacketBuffer buf = DefaultPacketBuffer.PacketBufferManager.allocate(BYTE_BYTES)) {
      Assertions.assertEquals(BYTE_BYTES, buf.capacity());
    }

    Assertions.assertFalse(smallBuffer.release());
    Assertions.assertFalse(mediumBuffer.release());
    Assertions.assertFalse(largeBuffer.release());
  }

  @Test
  public void noLeak() {
    for (int i = 0; i < 100; i++) {
      System.gc();
      if (i % 2 == 0) {
        DefaultPacketBuffer.FinalizablePacketBuffer allocate =
            DefaultPacketBuffer.PacketBufferManager.allocate(4);
        assert allocate.release();
      } else {
        DefaultPacketBuffer.FinalizablePacketBuffer allocate =
            DefaultPacketBuffer.PacketBufferManager.allocate(8);
        assert allocate.release();
      }
    }
  }

  @Test
  public void checkLeakEnabled() {
    ReferenceQueue<DefaultPacketBuffer.FinalizablePacketBuffer> RQ =
        new ReferenceQueue<DefaultPacketBuffer.FinalizablePacketBuffer>();
    int capacity = 4;
    long address = Native.malloc(capacity);
    DefaultPacketBuffer.FinalizablePacketBuffer buffer =
        new DefaultPacketBuffer.FinalizablePacketBuffer(
            new Pointer(address), PacketBuffer.ByteOrder.NATIVE, capacity, 0L, 0L);
    final DefaultPacketBuffer.PacketBufferReference bufRef =
        new DefaultPacketBuffer.PacketBufferReference(address, buffer, RQ);
    bufRef.fillStackTrace(true);
    Assertions.assertThrows(
        MemoryLeakException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            DefaultPacketBuffer.PacketBufferManager.checkLeak(bufRef, true);
          }
        });
  }

  @Test
  public void doubleFree() {
    final PacketBuffer buf = DefaultPacketBuffer.PacketBufferManager.allocate(4);
    Assertions.assertTrue(buf.release());
    Assertions.assertFalse(buf.release());
  }

  @Test
  public void illegalAccess() {
    final DefaultPacketBuffer.FinalizablePacketBuffer buf =
        DefaultPacketBuffer.PacketBufferManager.allocate(4);
    buf.setInt(0, 10);
    Assertions.assertEquals(10, buf.getInt(0));
    Assertions.assertTrue(buf.release());
    Assertions.assertThrows(
        MemoryAccessException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Assertions.assertEquals(10, buf.getInt(0));
          }
        });
  }

  @Test
  public void checkLeakDisabled() {
    ReferenceQueue<DefaultPacketBuffer.FinalizablePacketBuffer> RQ =
        new ReferenceQueue<DefaultPacketBuffer.FinalizablePacketBuffer>();
    int capacity = 4;
    long address = Native.malloc(capacity);
    DefaultPacketBuffer.FinalizablePacketBuffer buffer =
        new DefaultPacketBuffer.FinalizablePacketBuffer(
            new Pointer(address), PacketBuffer.ByteOrder.NATIVE, capacity, 0L, 0L);
    final DefaultPacketBuffer.PacketBufferReference bufRef =
        new DefaultPacketBuffer.PacketBufferReference(address, buffer, RQ);
    bufRef.fillStackTrace(false);
    DefaultPacketBuffer.PacketBufferManager.checkLeak(bufRef, false);
  }

  @Test
  public void cast() {
    try (final DefaultPacketBuffer.FinalizablePacketBuffer buf =
        DefaultPacketBuffer.PacketBufferManager.allocate(4)) {
      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              buf.cast(TestPacket.class);
            }
          });
      buf.setIndex(0, 4);
      Assertions.assertNotNull(buf.cast(TestPacket.class));
      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              buf.cast(Packet.Abstract.class);
            }
          });
      Assertions.assertThrows(
          IllegalStateException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              DefaultPacketBuffer.checkCastThrowable(
                  Integer.class, new InvocationTargetException(new IllegalStateException()));
            }
          });
      Assertions.assertNull(
          DefaultPacketBuffer.checkCastThrowable(Integer.class, new IllegalAccessError()));
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  static class TestPacket extends Packet.Abstract {

    public TestPacket(PacketBuffer buffer) {
      super(buffer);
    }

    @Override
    public PacketBuffer buffer() {
      return null;
    }

    @Override
    protected int size() {
      return 4;
    }
  }
}
