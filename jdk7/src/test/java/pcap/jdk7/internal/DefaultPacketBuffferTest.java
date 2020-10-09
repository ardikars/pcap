package pcap.jdk7.internal;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.spi.PacketBuffer;

@RunWith(JUnitPlatform.class)
public class DefaultPacketBuffferTest {

  private PacketBuffer smallBuffer;
  private PacketBuffer mediumBuffer;
  private PacketBuffer largeBuffer;

  @BeforeEach
  public void setUp() {
    smallBuffer = new DefaultPacketBuffer(Short.BYTES);
    mediumBuffer = new DefaultPacketBuffer(Integer.BYTES);
    largeBuffer = new DefaultPacketBuffer(Long.BYTES);
  }

  @Test
  public void useMemory() {
    DefaultPacketHeader header = new DefaultPacketHeader();
    DefaultPacketBuffer buffer = new DefaultPacketBuffer();
    buffer.userReference(header);
    buffer.reference.setValue(((DefaultPacketBuffer) smallBuffer).buffer);
    buffer.userReference(header);
  }

  @Test
  public void capacity() {
    Assertions.assertEquals(Short.BYTES, smallBuffer.capacity());
    Assertions.assertEquals(Integer.BYTES, mediumBuffer.capacity());
    Assertions.assertEquals(Long.BYTES, largeBuffer.capacity());
  }

  @Test
  public void readerIndex() {
    Assertions.assertEquals(0, smallBuffer.readerIndex());
    Assertions.assertEquals(0, mediumBuffer.readerIndex());
    Assertions.assertEquals(0, largeBuffer.readerIndex());
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.readerIndex(Short.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.readerIndex(Integer.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.readerIndex(Long.BYTES);
          }
        });
    smallBuffer.writerIndex(Short.BYTES);
    mediumBuffer.writerIndex(Integer.BYTES);
    largeBuffer.writerIndex(Long.BYTES);
    Assertions.assertEquals(Short.BYTES, smallBuffer.readerIndex(Short.BYTES).readerIndex());
    Assertions.assertEquals(Integer.BYTES, mediumBuffer.readerIndex(Integer.BYTES).readerIndex());
    Assertions.assertEquals(Long.BYTES, largeBuffer.readerIndex(Long.BYTES).readerIndex());
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.readerIndex(-Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.readerIndex(-Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.readerIndex(-Byte.BYTES);
          }
        });
  }

  @Test
  public void writerIndex() {
    Assertions.assertEquals(0, smallBuffer.writerIndex());
    Assertions.assertEquals(0, mediumBuffer.writerIndex());
    Assertions.assertEquals(0, largeBuffer.writerIndex());
    Assertions.assertEquals(Short.BYTES, smallBuffer.writerIndex(Short.BYTES).writerIndex());
    Assertions.assertEquals(Integer.BYTES, mediumBuffer.writerIndex(Integer.BYTES).writerIndex());
    Assertions.assertEquals(Long.BYTES, largeBuffer.writerIndex(Long.BYTES).writerIndex());
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.writerIndex(-Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.writerIndex(-Byte.BYTES);
          }
        });

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.writerIndex(-Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.writerIndex(Short.BYTES + Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.writerIndex(Integer.BYTES + Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.writerIndex(Long.BYTES + Byte.BYTES);
          }
        });
    smallBuffer.readerIndex(Short.BYTES);
    mediumBuffer.readerIndex(Integer.BYTES);
    largeBuffer.readerIndex(Long.BYTES);
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.writerIndex(Short.BYTES - Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.writerIndex(Integer.BYTES - Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.writerIndex(Long.BYTES - Byte.BYTES);
          }
        });
  }

  @Test
  public void setIndex() {
    smallBuffer.setIndex(Short.BYTES, Short.BYTES);
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.setIndex(Short.BYTES, Short.BYTES - Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.setIndex(Short.BYTES, Short.BYTES + Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.setIndex(Short.BYTES, -Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.setIndex(Short.BYTES, Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.setIndex(-Byte.BYTES, Short.BYTES);
          }
        });
    //
    mediumBuffer.setIndex(Integer.BYTES, Integer.BYTES);
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.setIndex(Integer.BYTES, Integer.BYTES - Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.setIndex(Integer.BYTES, Integer.BYTES + Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.setIndex(Integer.BYTES, -Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.setIndex(Integer.BYTES, Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.setIndex(-Byte.BYTES, Integer.BYTES);
          }
        });
    //
    largeBuffer.setIndex(Long.BYTES, Long.BYTES);
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setIndex(Long.BYTES, Long.BYTES - Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setIndex(Long.BYTES, Long.BYTES + Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setIndex(Long.BYTES, -Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setIndex(Long.BYTES, Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setIndex(-Byte.BYTES, Long.BYTES);
          }
        });
  }

  @Test
  public void readableBytes() {
    Assertions.assertEquals(0, smallBuffer.readableBytes());
    Assertions.assertEquals(Short.BYTES, smallBuffer.writerIndex(Short.BYTES).readableBytes());
    Assertions.assertEquals(0, mediumBuffer.readableBytes());
    Assertions.assertEquals(Integer.BYTES, mediumBuffer.writerIndex(Integer.BYTES).readableBytes());
    Assertions.assertEquals(0, largeBuffer.readableBytes());
    Assertions.assertEquals(Long.BYTES, largeBuffer.writerIndex(Long.BYTES).readableBytes());
  }

  @Test
  public void writableBytes() {
    Assertions.assertEquals(Short.BYTES, smallBuffer.writableBytes());
    Assertions.assertEquals(0, smallBuffer.writerIndex(Short.BYTES).writableBytes());
    Assertions.assertEquals(Integer.BYTES, mediumBuffer.writableBytes());
    Assertions.assertEquals(0, mediumBuffer.writerIndex(Integer.BYTES).writableBytes());
    Assertions.assertEquals(Long.BYTES, largeBuffer.writableBytes());
    Assertions.assertEquals(0, largeBuffer.writerIndex(Long.BYTES).writableBytes());
  }

  @Test
  public void isReadable() {
    Assertions.assertFalse(smallBuffer.isReadable());
    Assertions.assertTrue(smallBuffer.writerIndex(Short.BYTES).isReadable());
    Assertions.assertFalse(smallBuffer.isReadable(Short.BYTES + Byte.BYTES));
    Assertions.assertTrue(smallBuffer.setIndex(Byte.BYTES, Short.BYTES).isReadable(Byte.BYTES));
    Assertions.assertFalse(smallBuffer.isReadable(-Byte.BYTES));
    Assertions.assertFalse(smallBuffer.writerIndex(Short.BYTES).isReadable(-Byte.BYTES));

    Assertions.assertFalse(mediumBuffer.isReadable());
    Assertions.assertTrue(mediumBuffer.writerIndex(Integer.BYTES).isReadable());
    Assertions.assertFalse(mediumBuffer.isReadable(Integer.BYTES + Byte.BYTES));
    Assertions.assertTrue(mediumBuffer.setIndex(Byte.BYTES, Integer.BYTES).isReadable(Byte.BYTES));
    Assertions.assertFalse(mediumBuffer.isReadable(-Byte.BYTES));
    Assertions.assertFalse(mediumBuffer.writerIndex(Integer.BYTES).isReadable(-Byte.BYTES));

    Assertions.assertFalse(largeBuffer.isReadable());
    Assertions.assertTrue(largeBuffer.writerIndex(Long.BYTES).isReadable());
    Assertions.assertFalse(largeBuffer.isReadable(Long.BYTES + Byte.BYTES));
    Assertions.assertTrue(largeBuffer.setByte(Byte.BYTES, Long.BYTES).isReadable(Byte.BYTES));
    Assertions.assertFalse(largeBuffer.isReadable(-Byte.BYTES));
    Assertions.assertFalse(largeBuffer.writerIndex(Long.BYTES).isReadable(-Byte.BYTES));
  }

  @Test
  public void isWritable() {
    Assertions.assertTrue(smallBuffer.isWritable());
    Assertions.assertFalse(smallBuffer.setIndex(Short.BYTES, Short.BYTES).isWritable());
    Assertions.assertFalse(smallBuffer.setIndex(0, 0).isWritable(Short.BYTES + Byte.BYTES));
    Assertions.assertTrue(smallBuffer.setIndex(Byte.BYTES, Byte.BYTES).isWritable(Byte.BYTES));
    Assertions.assertFalse(smallBuffer.setIndex(0, 0).isWritable(-Byte.BYTES));
    Assertions.assertFalse(smallBuffer.setIndex(0, Short.BYTES).isWritable(-Byte.BYTES));

    Assertions.assertTrue(mediumBuffer.isWritable());
    Assertions.assertFalse(mediumBuffer.setIndex(Integer.BYTES, Integer.BYTES).isWritable());
    Assertions.assertFalse(mediumBuffer.setIndex(0, 0).isWritable(Integer.BYTES + Byte.BYTES));
    Assertions.assertTrue(mediumBuffer.setIndex(Byte.BYTES, Byte.BYTES).isWritable(Byte.BYTES));
    Assertions.assertFalse(mediumBuffer.setIndex(0, 0).isWritable(-Byte.BYTES));
    Assertions.assertFalse(mediumBuffer.setIndex(0, Integer.BYTES).isWritable(-Byte.BYTES));

    Assertions.assertTrue(largeBuffer.isWritable());
    Assertions.assertFalse(largeBuffer.setIndex(Long.BYTES, Long.BYTES).isWritable());
    Assertions.assertFalse(largeBuffer.setIndex(0, 0).isWritable(Long.BYTES + Byte.BYTES));
    Assertions.assertTrue(largeBuffer.setIndex(Byte.BYTES, Byte.BYTES).isWritable(Byte.BYTES));
    Assertions.assertFalse(largeBuffer.setIndex(0, 0).isWritable(-Byte.BYTES));
    Assertions.assertFalse(largeBuffer.setIndex(0, Long.BYTES).isWritable(-Byte.BYTES));
  }

  @Test
  public void markReader() {
    Assertions.assertEquals(0, smallBuffer.markReaderIndex().resetReaderIndex().readerIndex());
    Assertions.assertEquals(
        Byte.BYTES,
        smallBuffer
            .setIndex(Byte.BYTES, Short.BYTES)
            .markReaderIndex()
            .readerIndex(Short.BYTES)
            .resetReaderIndex()
            .readerIndex());
    Assertions.assertEquals(0, mediumBuffer.markReaderIndex().resetReaderIndex().readerIndex());
    Assertions.assertEquals(
        Byte.BYTES,
        mediumBuffer
            .setIndex(Byte.BYTES, Integer.BYTES)
            .markReaderIndex()
            .readerIndex(Integer.BYTES)
            .resetReaderIndex()
            .readerIndex());
    Assertions.assertEquals(0, largeBuffer.markReaderIndex().resetReaderIndex().readerIndex());
    Assertions.assertEquals(
        Byte.BYTES,
        largeBuffer
            .setIndex(Byte.BYTES, Long.BYTES)
            .markReaderIndex()
            .readerIndex(Long.BYTES)
            .resetReaderIndex()
            .readerIndex());
  }

  @Test
  public void markWriter() {
    Assertions.assertEquals(0, smallBuffer.markReaderIndex().writerIndex());
    Assertions.assertEquals(
        Byte.BYTES,
        smallBuffer
            .setIndex(Byte.BYTES, Byte.BYTES)
            .markWriterIndex()
            .writerIndex(Short.BYTES)
            .resetWriterIndex()
            .writerIndex());
    Assertions.assertEquals(0, mediumBuffer.markReaderIndex().writerIndex());
    Assertions.assertEquals(
        Byte.BYTES,
        mediumBuffer
            .setIndex(Byte.BYTES, Byte.BYTES)
            .markWriterIndex()
            .writerIndex(Integer.BYTES)
            .resetWriterIndex()
            .writerIndex());
    Assertions.assertEquals(0, largeBuffer.markReaderIndex().writerIndex());
    Assertions.assertEquals(
        Byte.BYTES,
        largeBuffer
            .setIndex(Byte.BYTES, Byte.BYTES)
            .markWriterIndex()
            .writerIndex(Short.BYTES)
            .resetWriterIndex()
            .writerIndex());
  }

  @Test
  public void ensureWritable() {
    smallBuffer.ensureWritable(Byte.BYTES);
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.ensureWritable(-Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.setIndex(Short.BYTES, Short.BYTES).ensureWritable(Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.setIndex(0, 0).ensureWritable(Short.BYTES + Byte.BYTES);
          }
        });
    //
    mediumBuffer.ensureWritable(Byte.BYTES);
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.ensureWritable(-Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.setIndex(Integer.BYTES, Integer.BYTES).ensureWritable(Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.setIndex(0, 0).ensureWritable(Integer.BYTES + Byte.BYTES);
          }
        });
    //
    largeBuffer.ensureWritable(Byte.BYTES);
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.ensureWritable(-Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setIndex(Long.BYTES, Long.BYTES).ensureWritable(Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setIndex(0, 0).ensureWritable(Long.BYTES + Byte.BYTES);
          }
        });
  }

  @Test
  public void getBoolean() {
    for (int i = 0; i < Short.BYTES; i++) {
      smallBuffer.setByte(i, i);
      if (i < Byte.BYTES) {
        Assertions.assertFalse(smallBuffer.getBoolean(i));
      } else {
        Assertions.assertTrue(smallBuffer.getBoolean(i));
      }
    }
    for (int i = 0; i < Integer.BYTES; i++) {
      mediumBuffer.setByte(i, i);
      if (i < Byte.BYTES) {
        Assertions.assertFalse(mediumBuffer.getBoolean(i));
      } else {
        Assertions.assertTrue(mediumBuffer.getBoolean(i));
      }
    }
    for (int i = 0; i < Long.BYTES; i++) {
      largeBuffer.setByte(i, i);
      if (i < Byte.BYTES) {
        Assertions.assertFalse(largeBuffer.getBoolean(i));
      } else {
        Assertions.assertTrue(largeBuffer.getBoolean(i));
      }
    }
  }

  @Test
  public void getUnsignedByte() {
    for (int i = 0; i < Short.BYTES; i++) {
      smallBuffer.setByte(i, 0xFF);
      Assertions.assertEquals(0xFF, smallBuffer.getUnsignedByte(i));
    }
    for (int i = 0; i < Integer.BYTES; i++) {
      mediumBuffer.setByte(i, 0xFF);
      Assertions.assertEquals(0xFF, mediumBuffer.getUnsignedByte(i));
    }
    for (int i = 0; i < Long.BYTES; i++) {
      largeBuffer.setByte(i, 0xFF);
      Assertions.assertEquals(0xFF, largeBuffer.getUnsignedByte(i));
    }
  }

  @Test
  public void getShortRE() {
    for (int i = 0; i < Short.BYTES / Short.BYTES; i++) {
      smallBuffer.setShort(i, i);
      Assertions.assertEquals(Short.reverseBytes((short) i), smallBuffer.getShortRE(i));
    }
    for (int i = 0; i < Integer.BYTES / Short.BYTES; i++) {
      mediumBuffer.setShort(i, i);
      Assertions.assertEquals(Short.reverseBytes((short) i), mediumBuffer.getShortRE(i));
    }
    for (int i = 0; i < Long.BYTES / Short.BYTES; i++) {
      largeBuffer.setShort(i, i);
      Assertions.assertEquals(Short.reverseBytes((short) i), largeBuffer.getShortRE(i));
    }
  }

  @Test
  public void getUnsignedShort() {
    for (int i = 0; i < Short.BYTES / Short.BYTES; i++) {
      smallBuffer.setShort(i, 0xFFFF);
      Assertions.assertEquals(0xFFFF, smallBuffer.getUnsignedShort(i));
    }
    for (int i = 0; i < Integer.BYTES / Short.BYTES; i++) {
      mediumBuffer.setShort(i, 0xFFFF);
      Assertions.assertEquals(0xFFFF, mediumBuffer.getUnsignedShort(i));
    }
    for (int i = 0; i < Long.BYTES / Short.BYTES; i++) {
      largeBuffer.setShort(i, 0xFFFF);
      Assertions.assertEquals(0xFFFF, largeBuffer.getUnsignedShort(i));
    }
  }

  @Test
  public void getUnsignedShortRE() {
    for (int i = 0; i < Short.BYTES / Short.BYTES; i++) {
      smallBuffer.setShort(i, 0xFFFF);
      Assertions.assertEquals(
          Short.reverseBytes((short) 0xFFFF), smallBuffer.getUnsignedShortRE(i));
    }
    for (int i = 0; i < Integer.BYTES / Short.BYTES; i++) {
      mediumBuffer.setShort(i, 0xFFFF);
      Assertions.assertEquals(
          Short.reverseBytes((short) 0xFFFF), mediumBuffer.getUnsignedShortRE(i));
    }
    for (int i = 0; i < Long.BYTES / Short.BYTES; i++) {
      largeBuffer.setShort(i, 0xFFFF);
      Assertions.assertEquals(
          Short.reverseBytes((short) 0xFFFF), largeBuffer.getUnsignedShortRE(i));
    }
  }

  @Test
  public void getIntRE() {
    for (int i = 0; i < Integer.BYTES / Integer.BYTES; i++) {
      mediumBuffer.setInt(i, i);
      Assertions.assertEquals(Integer.reverseBytes(i), mediumBuffer.getIntRE(i));
    }
    for (int i = 0; i < Long.BYTES / Integer.BYTES; i++) {
      largeBuffer.setInt(i, i);
      Assertions.assertEquals(Integer.reverseBytes(i), largeBuffer.getIntRE(i));
    }
  }

  @Test
  public void getUnsignedInt() {
    for (int i = 0; i < Integer.BYTES / Integer.BYTES; i++) {
      mediumBuffer.setInt(i, 0xFFFFFFFF);
      Assertions.assertEquals(0xFFFFFFFFL, mediumBuffer.getUnsignedInt(i));
    }
    for (int i = 0; i < Long.BYTES / Integer.BYTES; i++) {
      largeBuffer.setInt(i, 0xFFFFFFFF);
      Assertions.assertEquals(0xFFFFFFFFL, largeBuffer.getUnsignedInt(i));
    }
  }

  @Test
  public void getUnsignedIntRE() {
    for (int i = 0; i < Integer.BYTES / Integer.BYTES; i++) {
      mediumBuffer.setInt(i, 0xFFFFFFFF);
      Assertions.assertEquals(Integer.reverseBytes(0xFFFFFFFF), mediumBuffer.getUnsignedIntRE(i));
    }
    for (int i = 0; i < Long.BYTES / Integer.BYTES; i++) {
      largeBuffer.setInt(i, 0xFFFFFFFF);
      Assertions.assertEquals(Integer.reverseBytes(0xFFFFFFFF), largeBuffer.getUnsignedIntRE(i));
    }
  }

  @Test
  public void getLongRE() {
    for (int i = 0; i < Long.BYTES / Long.BYTES; i++) {
      largeBuffer.setLong(i, 0xFFFFFFFFFFFFFFFFL);
      Assertions.assertEquals(Long.reverseBytes(0xFFFFFFFFFFFFFFFFL), largeBuffer.getLongRE(i));
    }
  }

  @Test
  public void getFloat() {
    for (int i = 0; i < Integer.BYTES / Integer.BYTES; i++) {
      mediumBuffer.setFloat(i, i + 0.5F);
      Assertions.assertEquals(i + 0.5F, mediumBuffer.getFloat(i));
    }
    for (int i = 0; i < Long.BYTES / Integer.BYTES; i++) {
      largeBuffer.setFloat(i, i + 0.5F);
      Assertions.assertEquals(i + 0.5F, largeBuffer.getFloat(i));
    }
  }

  @Test
  public void getFloatRE() {
    for (int i = 0; i < Integer.BYTES / Integer.BYTES; i++) {
      mediumBuffer.setFloat(i, i + 0.5F);
      Assertions.assertEquals(
          Float.intBitsToFloat(mediumBuffer.getIntRE(i)), mediumBuffer.getFloatRE(i));
    }
    for (int i = 0; i < Long.BYTES / Integer.BYTES; i++) {
      largeBuffer.setFloat(i, i + 0.5F);
      Assertions.assertEquals(
          Float.intBitsToFloat(largeBuffer.getIntRE(i)), largeBuffer.getFloatRE(i));
    }
  }

  @Test
  public void getDouble() {
    for (int i = 0; i < Long.BYTES / Long.BYTES; i++) {
      largeBuffer.setDouble(i, i + 0.5D);
      Assertions.assertEquals(i + 0.5D, largeBuffer.getDouble(i));
    }
  }

  @Test
  public void getDoubleRE() {
    for (int i = 0; i < Long.BYTES / Long.BYTES; i++) {
      largeBuffer.setDouble(i, i + 0.5D);
      Assertions.assertEquals(
          Double.longBitsToDouble(largeBuffer.getLongRE(i)), largeBuffer.getDoubleRE(i));
    }
  }

  @Test
  public void getBytes() {
    for (int i = 0; i < Short.BYTES; i++) {
      smallBuffer.setByte(i, i);
      Assertions.assertEquals(i, smallBuffer.getByte(i));
    }
    for (int i = 0; i < Integer.BYTES; i++) {
      mediumBuffer.setByte(i, i);
      Assertions.assertEquals(i, mediumBuffer.getByte(i));
    }

    smallBuffer.getBytes(0, largeBuffer, Short.BYTES);
    mediumBuffer.getBytes(0, largeBuffer, Integer.BYTES);
    smallBuffer.getBytes(0, largeBuffer, Short.BYTES);
    Assertions.assertEquals(0, largeBuffer.getByte(0));
    Assertions.assertEquals(1, largeBuffer.getByte(1));
    Assertions.assertEquals(0, largeBuffer.getByte(2));
    Assertions.assertEquals(1, largeBuffer.getByte(3));
    Assertions.assertEquals(2, largeBuffer.getByte(4));
    Assertions.assertEquals(3, largeBuffer.getByte(5));
    Assertions.assertEquals(0, largeBuffer.getByte(6));
    Assertions.assertEquals(1, largeBuffer.getByte(7));

    byte[] largeBytes = new byte[Long.BYTES];
    largeBuffer.resetWriterIndex();
    smallBuffer.getBytes(0, largeBytes, 0, Short.BYTES);
    mediumBuffer.getBytes(0, largeBytes, Short.BYTES, Integer.BYTES);
    smallBuffer.getBytes(0, largeBytes, Integer.BYTES + Short.BYTES, Short.BYTES);
    Assertions.assertEquals(largeBytes[0], largeBuffer.getByte(0));
    Assertions.assertEquals(largeBytes[1], largeBuffer.getByte(1));
    Assertions.assertEquals(largeBytes[2], largeBuffer.getByte(2));
    Assertions.assertEquals(largeBytes[3], largeBuffer.getByte(3));
    Assertions.assertEquals(largeBytes[4], largeBuffer.getByte(4));
    Assertions.assertEquals(largeBytes[5], largeBuffer.getByte(5));
    Assertions.assertEquals(largeBytes[6], largeBuffer.getByte(6));
    Assertions.assertEquals(largeBytes[7], largeBuffer.getByte(7));

    byte[] bufBytes = new byte[Long.BYTES];
    largeBuffer.getBytes(0, bufBytes);
    Assertions.assertArrayEquals(largeBytes, bufBytes);

    PacketBuffer newBuf = new DefaultPacketBuffer((int) largeBuffer.capacity());
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
            largeBuffer.getBytes(0, smallBuffer.writerIndex(Short.BYTES), 0, Long.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.getBytes(0, new byte[] {0, 0}, 0, Long.BYTES);
          }
        });
  }

  @Test
  public void getCharSequace() {
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
    Assertions.assertEquals("Hi", smallBuffer.getCharSequence(0, Short.BYTES, charset));
    Assertions.assertEquals("Hi", mediumBuffer.getCharSequence(0, Short.BYTES, charset));
    Assertions.assertEquals("Hi", largeBuffer.getCharSequence(0, Short.BYTES, charset));
  }

  @Test
  public void setBoolean() {
    for (int i = 0; i < Short.BYTES; i++) {
      smallBuffer.setBoolean(i, i % 2 == 0);
      if (i % 2 == 0) {
        Assertions.assertTrue(smallBuffer.getByte(i) == 1);
      } else {
        Assertions.assertTrue(smallBuffer.getByte(i) == 0);
      }
    }
    for (int i = 0; i < Integer.BYTES; i++) {
      mediumBuffer.setBoolean(i, i % 2 == 0);
      if (i % 2 == 0) {
        Assertions.assertTrue(mediumBuffer.getByte(i) == 1);
      } else {
        Assertions.assertTrue(mediumBuffer.getByte(i) == 0);
      }
    }
    for (int i = 0; i < Long.BYTES; i++) {
      largeBuffer.setBoolean(i, i % 2 == 0);
      if (i % 2 == 0) {
        Assertions.assertTrue(largeBuffer.getByte(i) == 1);
      } else {
        Assertions.assertTrue(largeBuffer.getByte(i) == 0);
      }
    }
  }

  @Test
  public void setShortRE() {
    for (int i = 0; i < Short.BYTES / Short.BYTES; i++) {
      smallBuffer.setShortRE(i, i);
      Assertions.assertEquals(Short.reverseBytes((short) i), smallBuffer.getShort(i));
    }
    for (int i = 0; i < Integer.BYTES / Short.BYTES; i++) {
      mediumBuffer.setShortRE(i, i);
      Assertions.assertEquals(Short.reverseBytes((short) i), mediumBuffer.getShort(i));
    }
    for (int i = 0; i < Long.BYTES / Short.BYTES; i++) {
      largeBuffer.setShortRE(i, i);
      Assertions.assertEquals(Short.reverseBytes((short) i), largeBuffer.getShort(i));
    }
  }

  @Test
  public void setIntRE() {
    for (int i = 0; i < Integer.BYTES / Integer.BYTES; i++) {
      mediumBuffer.setIntRE(i, i);
      Assertions.assertEquals(Integer.reverseBytes(i), mediumBuffer.getInt(i));
    }
    for (int i = 0; i < Long.BYTES / Integer.BYTES; i++) {
      largeBuffer.setIntRE(i, i);
      Assertions.assertEquals(Integer.reverseBytes(i), largeBuffer.getInt(i));
    }
  }

  @Test
  public void setLongRE() {
    for (int i = 0; i < Long.BYTES / Long.BYTES; i++) {
      largeBuffer.setLongRE(i, 0xFFFFFFFFFFFFFFFFL);
      Assertions.assertEquals(Long.reverseBytes(0xFFFFFFFFFFFFFFFFL), largeBuffer.getLong(i));
    }
  }

  @Test
  public void setFloat() {
    for (int i = 0; i < Integer.BYTES / Integer.BYTES; i++) {
      mediumBuffer.setFloat(i, i + 0.5F);
      Assertions.assertEquals(i + 0.5F, mediumBuffer.getFloat(i));
    }
    for (int i = 0; i < Long.BYTES / Integer.BYTES; i++) {
      largeBuffer.setFloat(i, i + 0.5F);
      Assertions.assertEquals(i + 0.5F, largeBuffer.getFloat(i));
    }
  }

  @Test
  public void setFloatRE() {
    for (int i = 0; i < Integer.BYTES / Integer.BYTES; i++) {
      mediumBuffer.setFloatRE(i, i + 0.5F);
      Assertions.assertEquals(
          Float.intBitsToFloat(mediumBuffer.getIntRE(i)), mediumBuffer.getFloatRE(i));
    }
    for (int i = 0; i < Long.BYTES / Integer.BYTES; i++) {
      largeBuffer.setFloatRE(i, i + 0.5F);
      Assertions.assertEquals(
          Float.intBitsToFloat(largeBuffer.getIntRE(i)), largeBuffer.getFloatRE(i));
    }
  }

  @Test
  public void setDouble() {
    for (int i = 0; i < Long.BYTES / Long.BYTES; i++) {
      largeBuffer.setDouble(i, i + 0.5D);
      Assertions.assertEquals(i + 0.5D, largeBuffer.getDouble(i));
    }
  }

  @Test
  public void setDoubleRE() {
    for (int i = 0; i < Long.BYTES / Long.BYTES; i++) {
      largeBuffer.setDoubleRE(i, i + 0.5D);
      Assertions.assertEquals(
          Double.longBitsToDouble(largeBuffer.getLongRE(i)), largeBuffer.getDoubleRE(i));
    }
  }

  @Test
  public void setBytes() {
    for (int i = 0; i < Short.BYTES; i++) {
      smallBuffer.setByte(i, i);
      Assertions.assertEquals(i, smallBuffer.getByte(i));
    }
    for (int i = 0; i < Integer.BYTES; i++) {
      mediumBuffer.setByte(i, i);
      Assertions.assertEquals(i, mediumBuffer.getByte(i));
    }
    smallBuffer.setIndex(0, Short.BYTES);
    mediumBuffer.setIndex(0, Integer.BYTES);

    largeBuffer.setBytes(0, smallBuffer);
    largeBuffer.setBytes(Short.BYTES, mediumBuffer);
    smallBuffer.setIndex(0, Short.BYTES);
    largeBuffer.setBytes(Integer.BYTES + Short.BYTES, smallBuffer);

    Assertions.assertEquals(0, largeBuffer.getByte(0));
    Assertions.assertEquals(1, largeBuffer.getByte(1));
    Assertions.assertEquals(0, largeBuffer.getByte(2));
    Assertions.assertEquals(1, largeBuffer.getByte(3));
    Assertions.assertEquals(2, largeBuffer.getByte(4));
    Assertions.assertEquals(3, largeBuffer.getByte(5));
    Assertions.assertEquals(0, largeBuffer.getByte(6));
    Assertions.assertEquals(1, largeBuffer.getByte(7));

    byte[] bytes = new byte[Long.BYTES];
    for (int i = 0; i < bytes.length; i++) {
      bytes[i] = (byte) i;
    }
    largeBuffer.setIndex(0, 0);
    largeBuffer.setBytes(0, bytes, 0, bytes.length);
    for (int i = 0; i < Byte.BYTES; i++) {
      Assertions.assertEquals(i, largeBuffer.getByte(0));
    }
    largeBuffer.setIndex(0, 0);
    largeBuffer.setBytes(0, bytes);
    for (int i = 0; i < Byte.BYTES; i++) {
      Assertions.assertEquals(i, largeBuffer.getByte(0));
    }
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setBytes(0, null, Short.BYTES);
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setBytes(0, null, Integer.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.setIndex(Byte.BYTES, Short.BYTES);
            largeBuffer.setBytes(0, smallBuffer, Short.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.setIndex(Short.BYTES, Integer.BYTES);
            largeBuffer.setBytes(0, smallBuffer, Integer.BYTES);
          }
        });

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setBytes(0, smallBuffer, 1, Short.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setBytes(0, mediumBuffer, 1, Integer.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setBytes(0, bytes, 1, Long.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setBytes(0, bytes, 1, Long.BYTES);
          }
        });
  }

  @Test
  public void setCharSequace() {
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
    Assertions.assertEquals("Hi", smallBuffer.getCharSequence(0, Short.BYTES, charset));
    Assertions.assertEquals("Hi", mediumBuffer.getCharSequence(0, Short.BYTES, charset));
    Assertions.assertEquals("Hi", largeBuffer.getCharSequence(0, Short.BYTES, charset));
  }

  @Test
  public void readBoolean() {
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
  }

  @Test
  public void readByte() {
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
    for (int i = 0; i < Short.BYTES; i++) {
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
    for (int i = 0; i < Integer.BYTES; i++) {
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
    for (int i = 0; i < Long.BYTES; i++) {
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
  }

  @Test
  public void readUnsignedByte() {
    for (int i = 0; i < Short.BYTES; i++) {
      smallBuffer.writeByte(i);
      Assertions.assertEquals(i, smallBuffer.readUnsignedByte());
    }
    for (int i = 0; i < Integer.BYTES; i++) {
      mediumBuffer.writeByte(i);
      Assertions.assertEquals(i, mediumBuffer.readUnsignedByte());
    }
    for (int i = 0; i < Long.BYTES; i++) {
      largeBuffer.writeByte(i);
      Assertions.assertEquals(i, largeBuffer.readUnsignedByte());
    }
  }

  @Test
  public void readShort() {
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
    for (int i = 0; i < Short.BYTES / Short.BYTES; i++) {
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
    for (int i = 0; i < Integer.BYTES / Short.BYTES; i++) {
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
    for (int i = 0; i < Long.BYTES / Short.BYTES; i++) {
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
  }

  @Test
  public void readShortRE() {
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
    for (int i = 0; i < Short.BYTES / Short.BYTES; i++) {
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
    for (int i = 0; i < Integer.BYTES / Short.BYTES; i++) {
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
    for (int i = 0; i < Long.BYTES / Short.BYTES; i++) {
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
  }

  @Test
  public void readUnsignedShort() {
    for (int i = 0; i < Short.BYTES / Short.BYTES; i++) {
      smallBuffer.writeShort(0xFFFF);
      Assertions.assertEquals(0xFFFF, smallBuffer.readUnsignedShort());
    }
    for (int i = 0; i < Integer.BYTES / Short.BYTES; i++) {
      mediumBuffer.writeShort(0xFFFF);
      Assertions.assertEquals(0xFFFF, mediumBuffer.readUnsignedShort());
    }
    for (int i = 0; i < Long.BYTES / Short.BYTES; i++) {
      largeBuffer.writeShort(0xFFFF);
      Assertions.assertEquals(0xFFFF, largeBuffer.readUnsignedShort());
    }
  }

  @Test
  public void readUnsignedShortRE() {
    for (int i = 0; i < Short.BYTES / Short.BYTES; i++) {
      smallBuffer.writeShortRE(0xFFFF);
      Assertions.assertEquals(0xFFFF, smallBuffer.readUnsignedShortRE());
    }
    for (int i = 0; i < Integer.BYTES / Short.BYTES; i++) {
      mediumBuffer.writeShortRE(0xFFFF);
      Assertions.assertEquals(0xFFFF, mediumBuffer.readUnsignedShortRE());
    }
    for (int i = 0; i < Long.BYTES / Short.BYTES; i++) {
      largeBuffer.writeShortRE(0xFFFF);
      Assertions.assertEquals(0xFFFF, largeBuffer.readUnsignedShortRE());
    }
  }

  @Test
  public void readInt() {
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
    for (int i = 0; i < Integer.BYTES / Integer.BYTES; i++) {
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
    for (int i = 0; i < Long.BYTES / Integer.BYTES; i++) {
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
  }

  @Test
  public void readIntRE() {
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
    for (int i = 0; i < Integer.BYTES / Integer.BYTES; i++) {
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
    for (int i = 0; i < Long.BYTES / Integer.BYTES; i++) {
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
  }

  @Test
  public void readUnsignedInt() {
    for (int i = 0; i < Integer.BYTES / Integer.BYTES; i++) {
      mediumBuffer.writeInt(0xFFFFFFFF);
      Assertions.assertEquals(0xFFFFFFFFL, mediumBuffer.readUnsignedInt());
    }
    for (int i = 0; i < Long.BYTES / Integer.BYTES; i++) {
      largeBuffer.writeInt(0xFFFFFFFF);
      Assertions.assertEquals(0xFFFFFFFFL, largeBuffer.readUnsignedInt());
    }
  }

  @Test
  public void readUnsignedIntRE() {
    for (int i = 0; i < Integer.BYTES / Integer.BYTES; i++) {
      mediumBuffer.writeIntRE(0xFFFFFFFF);
      Assertions.assertEquals(0xFFFFFFFFL, mediumBuffer.readUnsignedIntRE());
    }
    for (int i = 0; i < Long.BYTES / Integer.BYTES; i++) {
      largeBuffer.writeIntRE(0xFFFFFFFF);
      Assertions.assertEquals(0xFFFFFFFFL, largeBuffer.readUnsignedIntRE());
    }
  }

  @Test
  public void readFloat() {
    for (int i = 0; i < Integer.BYTES / Integer.BYTES; i++) {
      mediumBuffer.writeFloat(i + 0.5F);
      Assertions.assertEquals(i + 0.5F, mediumBuffer.readFloat());
    }
    for (int i = 0; i < Long.BYTES / Integer.BYTES; i++) {
      largeBuffer.writeFloat(i + 0.5F);
      Assertions.assertEquals(i + 0.5F, largeBuffer.readFloat());
    }
  }

  @Test
  public void readFloatRE() {
    for (int i = 0; i < Integer.BYTES / Integer.BYTES; i++) {
      mediumBuffer.writeFloatRE(i + 0.5F);
      Assertions.assertEquals(i + 0.5F, mediumBuffer.readFloatRE());
    }
    for (int i = 0; i < Long.BYTES / Integer.BYTES; i++) {
      largeBuffer.writeFloatRE(i + 0.5F);
      Assertions.assertEquals(i + 0.5F, largeBuffer.readFloatRE());
    }
  }

  @Test
  public void readDouble() {
    for (int i = 0; i < Long.BYTES / Long.BYTES; i++) {
      largeBuffer.writeDouble(i + 0.5D);
      Assertions.assertEquals(i + 0.5D, largeBuffer.readDouble());
    }
  }

  @Test
  public void readDoubleRE() {
    for (int i = 0; i < Long.BYTES / Long.BYTES; i++) {
      largeBuffer.writeDoubleRE(i + 0.5D);
      Assertions.assertEquals(i + 0.5D, largeBuffer.readDoubleRE());
    }
  }

  @Test
  public void readLong() {
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
  }

  @Test
  public void readLongRE() {
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
  }

  @Test
  public void readBytes() {
    byte[] smallBytesDst = new byte[Short.BYTES];
    DefaultPacketBuffer smallBufDst = new DefaultPacketBuffer(Short.BYTES);
    byte[] mediumBytesDst = new byte[Integer.BYTES];
    DefaultPacketBuffer mediumBufDst = new DefaultPacketBuffer(Integer.BYTES);
    byte[] largeBytesDst = new byte[Long.BYTES];
    DefaultPacketBuffer largeBufDst = new DefaultPacketBuffer(Long.BYTES);

    for (int i = 0; i < Short.BYTES; i++) {
      smallBuffer.writeByte(i);
    }
    for (int i = 0; i < Integer.BYTES; i++) {
      mediumBuffer.writeByte(i);
    }
    for (int i = 0; i < Long.BYTES; i++) {
      largeBuffer.writeByte(i);
    }
    // PacketBuffer readBytes(PacketBuffer dst)
    Assertions.assertEquals(smallBuffer.writerIndex(), Short.BYTES);
    smallBuffer.readBytes(smallBufDst);
    smallBuffer.setIndex(0, Short.BYTES);
    smallBufDst.setIndex(0, Short.BYTES);
    for (int i = 0; i < Short.BYTES; i++) {
      Assertions.assertEquals(smallBuffer.readByte(), smallBufDst.readByte());
    }
    Assertions.assertEquals(mediumBuffer.writerIndex(), Integer.BYTES);
    mediumBuffer.readBytes(mediumBufDst);
    mediumBuffer.setIndex(0, Integer.BYTES);
    mediumBufDst.setIndex(0, Integer.BYTES);
    for (int i = 0; i < Integer.BYTES; i++) {
      Assertions.assertEquals(mediumBuffer.readByte(), mediumBufDst.readByte());
    }
    Assertions.assertEquals(largeBuffer.writerIndex(), Long.BYTES);
    largeBuffer.readBytes(largeBufDst);
    largeBuffer.setIndex(0, Long.BYTES);
    largeBufDst.setIndex(0, Long.BYTES);
    for (int i = 0; i < Long.BYTES; i++) {
      Assertions.assertEquals(largeBuffer.readByte(), largeBufDst.readByte());
    }

    smallBuffer.setIndex(0, Short.BYTES);
    smallBufDst.setIndex(0, 0);
    mediumBuffer.setIndex(0, Integer.BYTES);
    mediumBufDst.setIndex(0, 0);
    largeBuffer.setIndex(0, Long.BYTES);
    largeBufDst.setIndex(0, 0);

    // PacketBuffer readBytes(PacketBuffer dst, long length)
    Assertions.assertEquals(smallBuffer.writerIndex(), Short.BYTES);
    smallBuffer.readBytes(smallBufDst, Short.BYTES);
    smallBuffer.setIndex(0, Short.BYTES);
    smallBufDst.setIndex(0, Short.BYTES);
    for (int i = 0; i < Short.BYTES; i++) {
      Assertions.assertEquals(smallBuffer.readByte(), smallBufDst.readByte());
    }
    Assertions.assertEquals(mediumBuffer.writerIndex(), Integer.BYTES);
    mediumBuffer.readBytes(mediumBufDst, Integer.BYTES);
    mediumBuffer.setIndex(0, Integer.BYTES);
    mediumBufDst.setIndex(0, Integer.BYTES);
    for (int i = 0; i < Integer.BYTES; i++) {
      Assertions.assertEquals(mediumBuffer.readByte(), mediumBufDst.readByte());
    }
    Assertions.assertEquals(largeBuffer.writerIndex(), Long.BYTES);
    largeBuffer.readBytes(largeBufDst, Long.BYTES);
    largeBuffer.setIndex(0, Long.BYTES);
    largeBufDst.setIndex(0, Long.BYTES);
    for (int i = 0; i < Long.BYTES; i++) {
      Assertions.assertEquals(largeBuffer.readByte(), largeBufDst.readByte());
    }

    smallBuffer.setIndex(Byte.BYTES, Short.BYTES);
    smallBufDst.setIndex(Byte.BYTES, Short.BYTES);
    mediumBuffer.setIndex(Byte.BYTES, Integer.BYTES);
    mediumBufDst.setIndex(Byte.BYTES, Integer.BYTES);
    largeBuffer.setIndex(Byte.BYTES, Long.BYTES);
    largeBufDst.setIndex(Byte.BYTES, Long.BYTES);

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
            smallBuffer.readBytes(smallBufDst, Short.BYTES);
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
            mediumBuffer.readBytes(mediumBufDst, Integer.BYTES);
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
            largeBuffer.readBytes(largeBufDst, Long.BYTES);
          }
        });

    // PacketBuffer readBytes(byte[] dst)
    smallBuffer.setIndex(0, Short.BYTES);
    smallBufDst.setIndex(0, 0);
    mediumBuffer.setIndex(0, Integer.BYTES);
    mediumBufDst.setIndex(0, 0);
    largeBuffer.setIndex(0, Long.BYTES);
    largeBufDst.setIndex(0, 0);

    smallBuffer.readBytes(smallBytesDst);
    for (int i = 0; i < Short.BYTES; i++) {
      Assertions.assertEquals(smallBuffer.getByte(i), smallBytesDst[i]);
    }
    mediumBuffer.readBytes(mediumBytesDst);
    for (int i = 0; i < Integer.BYTES; i++) {
      Assertions.assertEquals(mediumBuffer.getByte(i), mediumBytesDst[i]);
    }
    largeBuffer.readBytes(largeBytesDst);
    for (int i = 0; i < Long.BYTES; i++) {
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
            smallBuffer.readBytes(smallBytesDst, Byte.BYTES, Short.BYTES);
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
            mediumBuffer.readBytes(mediumBytesDst, Byte.BYTES, Integer.BYTES);
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
            largeBuffer.readBytes(largeBytesDst, Byte.BYTES, Long.BYTES);
          }
        });
    Assertions.assertTrue(smallBufDst.release());
    Assertions.assertTrue(mediumBufDst.release());
    Assertions.assertTrue(largeBufDst.release());
  }

  @Test
  public void skipBytes() {
    for (int i = 0; i < Long.BYTES; i++) {
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
  }

  @Test
  public void readCharSequence() {
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
    Assertions.assertEquals("Hi", smallBuffer.readCharSequence(Short.BYTES, charset));
    Assertions.assertEquals("Hi", mediumBuffer.readCharSequence(Short.BYTES, charset));
    Assertions.assertEquals("Hi", largeBuffer.readCharSequence(Short.BYTES, charset));
  }

  @Test
  public void writeBoolean() {
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
  }

  @Test
  public void writeByte() {
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.setIndex(0, Short.BYTES).writeByte(Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.setIndex(0, Integer.BYTES).writeByte(Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setIndex(0, Long.BYTES).writeByte(Byte.BYTES);
          }
        });
  }

  @Test
  public void writeShort() {
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.setIndex(0, Short.BYTES).writeShort(Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.setIndex(0, Integer.BYTES).writeShort(Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setIndex(0, Long.BYTES).writeShort(Byte.BYTES);
          }
        });
  }

  @Test
  public void writeShortRE() {
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.setIndex(0, Short.BYTES).writeShortRE(Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.setIndex(0, Integer.BYTES).writeShortRE(Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setIndex(0, Long.BYTES).writeShortRE(Byte.BYTES);
          }
        });
  }

  @Test
  public void writeInt() {
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.setIndex(0, Integer.BYTES).writeInt(Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setIndex(0, Long.BYTES).writeInt(Byte.BYTES);
          }
        });
  }

  @Test
  public void writeIntRE() {
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.setIndex(0, Integer.BYTES).writeIntRE(Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setIndex(0, Long.BYTES).writeIntRE(Byte.BYTES);
          }
        });
  }

  @Test
  public void writeLong() {
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setIndex(0, Long.BYTES).writeLong(Byte.BYTES);
          }
        });
  }

  @Test
  public void writeLongRE() {
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setIndex(0, Long.BYTES).writeLongRE(Byte.BYTES);
          }
        });
  }

  @Test
  public void writeFloat() {
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.setIndex(0, Integer.BYTES).writeFloat(Byte.BYTES + 0.5F);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setIndex(0, Long.BYTES).writeFloat(Byte.BYTES + 0.5F);
          }
        });
  }

  @Test
  public void writeFloatRE() {
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.setIndex(0, Integer.BYTES).writeFloatRE(Byte.BYTES + 0.5F);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setIndex(0, Long.BYTES).writeFloatRE(Byte.BYTES + 0.5F);
          }
        });
  }

  @Test
  public void writeDouble() {
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setIndex(0, Long.BYTES).writeDouble(Byte.BYTES + 0.5D);
          }
        });
  }

  @Test
  public void writeDoubleRE() {
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setIndex(0, Long.BYTES).writeDoubleRE(Byte.BYTES + 0.5D);
          }
        });
  }

  @Test
  public void writeBytes() {
    byte[] smallBytesDst = new byte[Short.BYTES];
    DefaultPacketBuffer smallBufSrc = new DefaultPacketBuffer(Short.BYTES);
    byte[] mediumBytesDst = new byte[Integer.BYTES];
    DefaultPacketBuffer mediumBufSrc = new DefaultPacketBuffer(Integer.BYTES);
    byte[] largeBytesDst = new byte[Long.BYTES];
    DefaultPacketBuffer largeBufSrc = new DefaultPacketBuffer(Long.BYTES);

    for (int i = 0; i < Short.BYTES; i++) {
      smallBufSrc.writeByte(i);
    }
    for (int i = 0; i < Integer.BYTES; i++) {
      mediumBufSrc.writeByte(i);
    }
    for (int i = 0; i < Long.BYTES; i++) {
      largeBufSrc.writeByte(i);
    }
    // PacketBuffer readBytes(PacketBuffer dst)
    Assertions.assertEquals(smallBufSrc.writerIndex(), Short.BYTES);
    smallBuffer.writeBytes(smallBufSrc);
    smallBuffer.setIndex(0, Short.BYTES);
    smallBufSrc.setIndex(0, Short.BYTES);
    for (int i = 0; i < Short.BYTES; i++) {
      Assertions.assertEquals(smallBuffer.readByte(), smallBufSrc.readByte());
    }
    Assertions.assertEquals(mediumBufSrc.writerIndex(), Integer.BYTES);
    mediumBuffer.writeBytes(mediumBufSrc);
    mediumBuffer.setIndex(0, Integer.BYTES);
    mediumBufSrc.setIndex(0, Integer.BYTES);
    for (int i = 0; i < Integer.BYTES; i++) {
      Assertions.assertEquals(mediumBuffer.readByte(), mediumBufSrc.readByte());
    }
    Assertions.assertEquals(largeBufSrc.writerIndex(), Long.BYTES);
    largeBuffer.writeBytes(largeBufSrc);
    largeBuffer.setIndex(0, Long.BYTES);
    largeBufSrc.setIndex(0, Long.BYTES);
    for (int i = 0; i < Long.BYTES; i++) {
      Assertions.assertEquals(largeBuffer.readByte(), largeBufSrc.readByte());
    }

    smallBufSrc.setIndex(0, Short.BYTES);
    smallBuffer.setIndex(0, 0);
    mediumBufSrc.setIndex(0, Integer.BYTES);
    mediumBuffer.setIndex(0, 0);
    largeBufSrc.setIndex(0, Long.BYTES);
    largeBuffer.setIndex(0, 0);

    // PacketBuffer readBytes(PacketBuffer dst, long length)
    Assertions.assertEquals(smallBufSrc.writerIndex(), Short.BYTES);
    smallBuffer.writeBytes(smallBufSrc, Short.BYTES);
    smallBuffer.setIndex(0, Short.BYTES);
    smallBufSrc.setIndex(0, Short.BYTES);
    for (int i = 0; i < Short.BYTES; i++) {
      Assertions.assertEquals(smallBuffer.readByte(), smallBufSrc.readByte());
    }
    Assertions.assertEquals(mediumBufSrc.writerIndex(), Integer.BYTES);
    mediumBuffer.writeBytes(mediumBufSrc, Integer.BYTES);
    mediumBuffer.setIndex(0, Integer.BYTES);
    mediumBufSrc.setIndex(0, Integer.BYTES);
    for (int i = 0; i < Integer.BYTES; i++) {
      Assertions.assertEquals(mediumBuffer.readByte(), mediumBufSrc.readByte());
    }
    Assertions.assertEquals(largeBufSrc.writerIndex(), Long.BYTES);
    largeBuffer.writeBytes(largeBufSrc, Long.BYTES);
    largeBuffer.setIndex(0, Long.BYTES);
    largeBufSrc.setIndex(0, Long.BYTES);
    for (int i = 0; i < Long.BYTES; i++) {
      Assertions.assertEquals(largeBuffer.readByte(), largeBufSrc.readByte());
    }

    smallBuffer.setIndex(Byte.BYTES, Short.BYTES);
    smallBufSrc.setIndex(Byte.BYTES, Short.BYTES);
    mediumBuffer.setIndex(Byte.BYTES, Integer.BYTES);
    mediumBufSrc.setIndex(Byte.BYTES, Integer.BYTES);
    largeBuffer.setIndex(Byte.BYTES, Long.BYTES);
    largeBufSrc.setIndex(Byte.BYTES, Long.BYTES);

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
            smallBuffer.writeBytes(smallBufSrc, Short.BYTES);
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
            mediumBuffer.writeBytes(mediumBufSrc, Integer.BYTES);
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
            largeBuffer.writeBytes(largeBufSrc, Long.BYTES);
          }
        });

    // PacketBuffer writeBytes(byte[] dst)
    smallBuffer.setIndex(0, Short.BYTES);
    smallBufSrc.setIndex(0, 0);
    mediumBuffer.setIndex(0, Integer.BYTES);
    mediumBufSrc.setIndex(0, 0);
    largeBuffer.setIndex(0, Long.BYTES);
    largeBufSrc.setIndex(0, 0);

    smallBuffer.readBytes(smallBytesDst);
    for (int i = 0; i < Short.BYTES; i++) {
      Assertions.assertEquals(smallBuffer.getByte(i), smallBytesDst[i]);
    }
    mediumBuffer.readBytes(mediumBytesDst);
    for (int i = 0; i < Integer.BYTES; i++) {
      Assertions.assertEquals(mediumBuffer.getByte(i), mediumBytesDst[i]);
    }
    largeBuffer.readBytes(largeBytesDst);
    for (int i = 0; i < Long.BYTES; i++) {
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
            smallBuffer.readBytes(smallBytesDst, Byte.BYTES, Short.BYTES);
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
            mediumBuffer.readBytes(mediumBytesDst, Byte.BYTES, Integer.BYTES);
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
            largeBuffer.readBytes(largeBytesDst, Byte.BYTES, Long.BYTES);
          }
        });
    Assertions.assertTrue(smallBufSrc.release());
    Assertions.assertTrue(mediumBufSrc.release());
    Assertions.assertTrue(largeBufSrc.release());
  }

  @Test
  public void writeCharSequence() {
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
    Assertions.assertEquals("Hi", smallBuffer.readCharSequence(Short.BYTES, charset));
    Assertions.assertEquals("Hi", mediumBuffer.readCharSequence(Short.BYTES, charset));
    Assertions.assertEquals("Hi", largeBuffer.readCharSequence(Short.BYTES, charset));
  }

  @Test
  public void byteOrder() {
    Assertions.assertEquals(PacketBuffer.ByteOrder.NATIVE, smallBuffer.byteOrder());
    Assertions.assertEquals(PacketBuffer.ByteOrder.NATIVE, mediumBuffer.byteOrder());
    Assertions.assertEquals(PacketBuffer.ByteOrder.NATIVE, largeBuffer.byteOrder());
    Assertions.assertThrows(
        UnsupportedOperationException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.byteOrder(PacketBuffer.ByteOrder.BIG_ENDIAN);
          }
        });
    Assertions.assertThrows(
        UnsupportedOperationException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.byteOrder(PacketBuffer.ByteOrder.BIG_ENDIAN);
          }
        });
    Assertions.assertThrows(
        UnsupportedOperationException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.byteOrder(PacketBuffer.ByteOrder.BIG_ENDIAN);
          }
        });
  }

  @Test
  public void copy() {
    for (int i = 0; i < Short.BYTES; i++) {
      smallBuffer.writeByte(i);
    }
    for (int i = 0; i < Integer.BYTES; i++) {
      mediumBuffer.writeByte(i);
    }
    for (int i = 0; i < Long.BYTES; i++) {
      largeBuffer.writeByte(i);
    }
    PacketBuffer smallCopy = smallBuffer.copy();
    PacketBuffer smallCopySliced = smallBuffer.copy(Byte.BYTES, Byte.BYTES);
    PacketBuffer mediumCopy = mediumBuffer.copy();
    PacketBuffer mediumCopySliced = mediumBuffer.copy(Short.BYTES, Short.BYTES);
    PacketBuffer largeCopy = largeBuffer.copy();
    PacketBuffer largeCopySliced = largeBuffer.copy(Integer.BYTES, Integer.BYTES);

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.copy(-Byte.BYTES, Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.copy(Byte.BYTES, Long.BYTES + Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.copy(-Byte.BYTES, Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.copy(Byte.BYTES, Long.BYTES + Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.copy(-Byte.BYTES, Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.copy(Byte.BYTES, Long.BYTES + Byte.BYTES);
          }
        });

    for (int i = 0; i < Short.BYTES; i++) {
      Assertions.assertEquals(smallCopy.getByte(i), smallBuffer.getByte(i));
    }
    for (int i = Byte.BYTES; i < Byte.BYTES + Byte.BYTES; i++) {
      Assertions.assertEquals(smallCopySliced.getByte(i - Byte.BYTES), smallBuffer.getByte(i));
    }
    for (int i = 0; i < Integer.BYTES; i++) {
      Assertions.assertEquals(mediumCopy.getByte(i), mediumBuffer.getByte(i));
    }
    for (int i = Short.BYTES; i < Short.BYTES + Short.BYTES; i++) {
      Assertions.assertEquals(mediumCopySliced.getByte(i - Short.BYTES), mediumBuffer.getByte(i));
    }
    for (int i = 0; i < Long.BYTES; i++) {
      Assertions.assertEquals(largeCopy.getByte(i), largeBuffer.getByte(i));
    }
    for (int i = Integer.BYTES; i < Integer.BYTES + Integer.BYTES; i++) {
      Assertions.assertEquals(largeCopySliced.getByte(i - Integer.BYTES), largeBuffer.getByte(i));
    }

    Assertions.assertTrue(smallCopy.release());
    Assertions.assertTrue(smallCopySliced.release());
    Assertions.assertTrue(mediumCopy.release());
    Assertions.assertTrue(mediumCopySliced.release());
    Assertions.assertTrue(largeCopy.release());
    Assertions.assertTrue(largeCopySliced.release());
  }

  @Test
  public void slice() {
    Assertions.assertEquals(0, smallBuffer.slice().capacity());
    Assertions.assertEquals(1, smallBuffer.writerIndex(Byte.BYTES).slice().capacity());
    Assertions.assertEquals(0, mediumBuffer.slice().capacity());
    Assertions.assertEquals(1, mediumBuffer.writerIndex(Byte.BYTES).slice().capacity());
    Assertions.assertEquals(0, largeBuffer.slice().capacity());
    Assertions.assertEquals(1, largeBuffer.writerIndex(Byte.BYTES).slice().capacity());

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.writerIndex(Short.BYTES).slice(-Byte.BYTES, Short.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.writerIndex(Short.BYTES).slice(0, Short.BYTES + Byte.BYTES);
          }
        });

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.writerIndex(Integer.BYTES).slice(-Byte.BYTES, Integer.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.writerIndex(Integer.BYTES).slice(0, Integer.BYTES + Byte.BYTES);
          }
        });

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.writerIndex(Long.BYTES).slice(-Byte.BYTES, Long.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.writerIndex(Long.BYTES).slice(0, Long.BYTES + Byte.BYTES);
          }
        });
  }

  @Test
  public void getByte() {
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.getByte(-Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.getByte(Short.BYTES + Byte.BYTES);
          }
        });

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.getByte(-Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.getByte(Integer.BYTES + Byte.BYTES);
          }
        });

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.getByte(-Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.getByte(Long.BYTES + Byte.BYTES);
          }
        });
  }

  @Test
  public void getShort() {
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.getShort(-Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.getShort(Short.BYTES + Byte.BYTES);
          }
        });

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.getShort(-Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.getShort(Integer.BYTES + Byte.BYTES);
          }
        });

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.getShort(-Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.getShort(Long.BYTES + Byte.BYTES);
          }
        });
  }

  @Test
  public void getInt() {
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.getInt(-Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.getInt(Integer.BYTES + Byte.BYTES);
          }
        });

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.getInt(-Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.getInt(Long.BYTES + Byte.BYTES);
          }
        });
  }

  @Test
  public void getLong() {
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.getLong(-Byte.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.getLong(Long.BYTES + Byte.BYTES);
          }
        });
  }

  @Test
  public void setByte() {
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.setByte(-Byte.BYTES, Short.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.setByte(Short.BYTES + Byte.BYTES, Short.BYTES);
          }
        });

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.setByte(-Byte.BYTES, Integer.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.setByte(Integer.BYTES + Byte.BYTES, Integer.BYTES);
          }
        });

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setByte(-Byte.BYTES, Long.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setByte(Long.BYTES + Byte.BYTES, Long.BYTES);
          }
        });
  }

  @Test
  public void setShort() {
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.setShort(-Byte.BYTES, Short.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.setShort(Short.BYTES + Byte.BYTES, Short.BYTES);
          }
        });

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.setShort(-Byte.BYTES, Integer.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.setShort(Integer.BYTES + Byte.BYTES, Integer.BYTES);
          }
        });

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setShort(-Byte.BYTES, Long.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setShort(Long.BYTES + Byte.BYTES, Long.BYTES);
          }
        });
  }

  @Test
  public void setInt() {
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.setInt(-Byte.BYTES, Integer.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.setInt(Integer.BYTES + Byte.BYTES, Integer.BYTES);
          }
        });

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setInt(-Byte.BYTES, Long.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setInt(Long.BYTES + Byte.BYTES, Long.BYTES);
          }
        });
  }

  @Test
  public void setLong() {
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setLong(-Byte.BYTES, Long.BYTES);
          }
        });
    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.setLong(Long.BYTES + Byte.BYTES, Long.BYTES);
          }
        });
  }

  @Test
  public void duplicate() {
    Assertions.assertEquals(smallBuffer.capacity(), smallBuffer.duplicate().capacity());
    Assertions.assertEquals(mediumBuffer.capacity(), mediumBuffer.duplicate().capacity());
    Assertions.assertEquals(largeBuffer.capacity(), largeBuffer.duplicate().capacity());
    Assertions.assertEquals(smallBuffer.writerIndex(), smallBuffer.duplicate().writerIndex());
    Assertions.assertEquals(mediumBuffer.writerIndex(), mediumBuffer.duplicate().writerIndex());
    Assertions.assertEquals(largeBuffer.writerIndex(), largeBuffer.duplicate().writerIndex());
    Assertions.assertEquals(smallBuffer.readerIndex(), smallBuffer.duplicate().readerIndex());
    Assertions.assertEquals(mediumBuffer.readerIndex(), mediumBuffer.duplicate().readerIndex());
    Assertions.assertEquals(largeBuffer.readerIndex(), largeBuffer.duplicate().readerIndex());
  }

  @Test
  public void unSlice() {
    PacketBuffer smallSlice = smallBuffer.slice(Byte.BYTES, Byte.BYTES);
    PacketBuffer mediumSlice = mediumBuffer.slice(Byte.BYTES, Short.BYTES);
    PacketBuffer largeSlice = largeBuffer.slice(Byte.BYTES, Integer.BYTES);
    Assertions.assertEquals(smallBuffer, ((PacketBuffer.Sliced) smallSlice).unSlice());
    Assertions.assertEquals(mediumBuffer, ((PacketBuffer.Sliced) mediumSlice).unSlice());
    Assertions.assertEquals(largeBuffer, ((PacketBuffer.Sliced) largeSlice).unSlice());
  }

  @Test
  public void release() {
    Assertions.assertFalse(smallBuffer.slice().release());
    Assertions.assertFalse(mediumBuffer.slice().release());
    Assertions.assertFalse(largeBuffer.slice().release());
    Assertions.assertFalse(new DefaultPacketBuffer().release());
  }

  @Test
  public void autoCloseable() throws Exception {
    Assertions.assertThrows(
        IllegalStateException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            smallBuffer.slice().close();
          }
        });
    Assertions.assertThrows(
        IllegalStateException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mediumBuffer.slice().close();
          }
        });
    Assertions.assertThrows(
        IllegalStateException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            largeBuffer.slice().close();
          }
        });
    try (PacketBuffer buf = new DefaultPacketBuffer(Byte.BYTES)) {
      Assertions.assertEquals(Byte.BYTES, buf.capacity());
    }
  }

  @AfterEach
  public void close() {
    Assertions.assertTrue(smallBuffer.release());
    Assertions.assertTrue(mediumBuffer.release());
    Assertions.assertTrue(largeBuffer.release());
  }
}
