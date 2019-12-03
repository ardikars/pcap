/** This code is licenced under the GPL version 2. */
package pcap.common.memory;

import java.nio.charset.Charset;

abstract class AbstractMemoryWriterAndReaderTest extends BaseTest {

  protected Memory memory;

  private final boolean pooled;

  AbstractMemoryWriterAndReaderTest() {
    this.pooled = false;
  }

  AbstractMemoryWriterAndReaderTest(boolean pooled) {
    this.pooled = pooled;
  }

  protected abstract MemoryAllocator memoryAllocator();

  public abstract void allocate();

  public abstract void deallocate();

  public abstract void booleanTest();

  protected void doBooleanTest() {
    memory.writeBoolean(true);
    memory.writeBoolean(false);
    memory.writeBoolean(true);
    assert memory.readBoolean();
    assert !memory.readBoolean();
    assert memory.readBoolean();
  }

  public abstract void byteTest();

  protected void doByteTest() {
    for (int i = 0; i < DEFAULT_CAPACITY; i++) {
      memory.writeByte(i);
    }
    for (int i = 0; i < DEFAULT_CAPACITY; i++) {
      assert memory.readByte() == (byte) i;
    }
  }

  public abstract void unsignedByteTest();

  protected void doUnsignedByteTest() {
    int value = (Byte.MAX_VALUE * 2) + 1;
    memory.writeByte(value);
    assert memory.readUnsignedByte() == (short) value;
    memory.readerIndex(0);
    assert memory.readByte() != value;
  }

  public abstract void shortTest();

  protected void doShortTest() {
    for (int i = 0; i < DEFAULT_CAPACITY / SHORT_SIZE; i++) {
      memory.writeShort(i + SHORT_SIZE);
    }
    for (int i = 0; i < DEFAULT_CAPACITY / SHORT_SIZE; i++) {
      assert memory.readShort() == (short) (i + SHORT_SIZE);
    }
  }

  public abstract void shortLETest();

  protected void doShortLETest() {
    for (int i = 0; i < DEFAULT_CAPACITY / SHORT_SIZE; i++) {
      memory.writeShortLE(i + SHORT_SIZE);
    }
    for (int i = 0; i < DEFAULT_CAPACITY / SHORT_SIZE; i++) {
      assert memory.readShortLE() == (short) (i + SHORT_SIZE);
    }
  }

  public abstract void unsignedShortTest();

  protected void doUnsignedShortTest() {
    int value = (Short.MAX_VALUE * 2) + 1;
    memory.writeShort(value);
    assert memory.readUnsignedShort() == value;
    memory.readerIndex(0);
    assert memory.readShort() != value;
  }

  public abstract void unsignedShortLETest();

  protected void doUnsignedShortLETest() {
    int value = (Short.MAX_VALUE * 2) + 1;
    memory.writeShortLE(value);
    assert memory.readUnsignedShortLE() == value;
    memory.readerIndex(0);
    assert memory.readShortLE() != value;
  }

  public abstract void intTest();

  protected void doIntTest() {
    for (int i = 0; i < DEFAULT_CAPACITY / INT_SIZE; i++) {
      memory.writeInt(i + INT_SIZE);
    }
    for (int i = 0; i < DEFAULT_CAPACITY / INT_SIZE; i++) {
      assert memory.readInt() == (i + INT_SIZE);
    }
  }

  public abstract void intLETest();

  protected void doIntLETest() {
    for (int i = 0; i < DEFAULT_CAPACITY / INT_SIZE; i++) {
      memory.writeIntLE(i + INT_SIZE);
    }
    for (int i = 0; i < DEFAULT_CAPACITY / INT_SIZE; i++) {
      assert memory.readIntLE() == (i + INT_SIZE);
    }
  }

  public abstract void unsignedIntTest();

  protected void doUnsignedIntTest() {
    memory.writeInt(0xffffffff);
    assert memory.readUnsignedInt() == 4294967295L;
    memory.readerIndex(0);
    assert memory.readInt() != 4294967295L;
  }

  public abstract void unsignedIntLETest();

  protected void doUnsignedIntLETest() {
    memory.writeIntLE(0xffffffff);
    assert memory.readUnsignedIntLE() == 4294967295L;
    memory.readerIndex(0);
    assert memory.readIntLE() != 4294967295L;
  }

  public abstract void floatTest();

  protected void doFloatTest() {
    float random = RANDOM.nextFloat();
    for (int i = 0; i < DEFAULT_CAPACITY / INT_SIZE; i++) {
      memory.writeFloat(i + INT_SIZE + random);
    }
    for (int i = 0; i < DEFAULT_CAPACITY / INT_SIZE; i++) {
      assert memory.readFloat() == (i + INT_SIZE + random);
    }
  }

  public abstract void floatLETest();

  protected void doFloatLETest() {
    float random = RANDOM.nextFloat();
    for (int i = 0; i < DEFAULT_CAPACITY / INT_SIZE; i++) {
      memory.writeFloatLE(i + INT_SIZE + random);
    }
    for (int i = 0; i < DEFAULT_CAPACITY / INT_SIZE; i++) {
      assert memory.readFloatLE() == (i + INT_SIZE + random);
    }
  }

  public abstract void longTest();

  protected void doLongTest() {
    for (int i = 0; i < DEFAULT_CAPACITY / LONG_SIZE; i++) {
      memory.writeLong(i + LONG_SIZE);
    }
    for (int i = 0; i < DEFAULT_CAPACITY / LONG_SIZE; i++) {
      assert memory.readLong() == (long) (i + LONG_SIZE);
    }
  }

  public abstract void longLETest();

  protected void doLongLETest() {
    for (int i = 0; i < DEFAULT_CAPACITY / LONG_SIZE; i++) {
      memory.writeLongLE(i + LONG_SIZE);
    }
    for (int i = 0; i < DEFAULT_CAPACITY / LONG_SIZE; i++) {
      assert memory.readLongLE() == (long) (i + LONG_SIZE);
    }
  }

  public abstract void doubleTest();

  protected void doDoubleTest() {
    double random = RANDOM.nextDouble();
    for (int i = 0; i < DEFAULT_CAPACITY / LONG_SIZE; i++) {
      memory.writeDouble(i + LONG_SIZE + random);
    }
    for (int i = 0; i < DEFAULT_CAPACITY / LONG_SIZE; i++) {
      assert memory.readDouble() == (i + LONG_SIZE + random);
    }
  }

  public abstract void doubleLETest();

  protected void doDoubleLETest() {
    double random = RANDOM.nextDouble();
    for (int i = 0; i < DEFAULT_CAPACITY / LONG_SIZE; i++) {
      memory.writeDoubleLE(i + LONG_SIZE + random);
    }
    for (int i = 0; i < DEFAULT_CAPACITY / LONG_SIZE; i++) {
      assert memory.readDoubleLE() == (i + LONG_SIZE + random);
    }
  }

  public abstract void writeBytesTest();

  protected void doWriteBytesTest() {
    memory.writeBytes(DUMMY);
    for (byte val : DUMMY) {
      assert memory.readByte() == val;
    }
    memory.readerIndex(0);
    memory.writerIndex(0);
    memory.writeBytes(DUMMY, 1, DUMMY.length - 1);
    for (int i = 0; i < DUMMY.length - 1; i++) {
      assert memory.getByte(i) == DUMMY[i + 1];
    }
    Memory memSrc = memoryAllocator().allocate(DUMMY.length);
    assert memSrc.capacity() == DUMMY.length;
    memSrc.writeBytes(DUMMY);
    memory.writerIndex(0);
    memory.writeBytes(memSrc);
    for (int i = 0; i < memSrc.capacity(); i++) {
      assert memory.getByte(i) == DUMMY[i];
    }
    memSrc.readerIndex(0);
    memSrc.writerIndex(5);
    memory.writerIndex(0);
    memory.writeBytes(memSrc, 2);
    for (int i = 0; i < 2; i++) {
      assert memory.getByte(i) == DUMMY[i];
    }
    memory.readerIndex(0);
    memory.writerIndex(0);
    memSrc.setByte(2, 2);
    memSrc.setByte(3, 3);
    memory.writeBytes(memSrc, 2, 2);
    for (int i = 0; i < 2; i++) {
      assert memory.getByte(i) == DUMMY[i + 2];
    }
    doRelease(memSrc);
  }

  public abstract void readBytesTest();

  protected void doReadBytesTest() {
    for (byte val : DUMMY) {
      memory.writeByte(val);
    }
    byte[] dst = new byte[DUMMY.length];
    memory.readBytes(dst);
    assert dst.length == DUMMY.length;
    for (int i = 0; i < dst.length; i++) {
      assert dst[i] == DUMMY[i];
    }
    dst = new byte[DUMMY.length];
    memory.readerIndex(0);
    memory.readBytes(dst, 1, dst.length - 1);
    for (int i = 1; i < dst.length - 1; i++) {
      assert dst[i] == DUMMY[i - 1];
    }
    memory.readerIndex(0);
    Memory dstMem = memoryAllocator().allocate(DUMMY.length);
    memory.readBytes(dstMem);
    for (int i = 0; i < dstMem.capacity(); i++) {
      assert memory.getByte(i) == DUMMY[i];
    }
    doRelease(dstMem);
    memory.readerIndex(0);
    dstMem = memoryAllocator().allocate(DUMMY.length);
    memory.readBytes(dstMem, DUMMY.length / BIT_SIZE);
    for (int i = 0; i < DUMMY.length / BIT_SIZE; i++) {
      assert memory.getByte(i) == dstMem.getByte(i);
    }
    doRelease(dstMem);
    memory.readerIndex(0);
    dstMem = memoryAllocator().allocate(DUMMY.length);
    memory.readBytes(dstMem, 1, dstMem.capacity() - 1);
    for (int i = 1; i < dstMem.capacity() - 1; i++) {
      assert dstMem.getByte(i) == DUMMY[i - 1];
    }
    doRelease(dstMem);
  }

  public abstract void writeReadCharSequaceTest();

  protected void doWriteReadCharSequaceTest() {
    String msg = "Hello java!.....";
    int length = msg.length();
    Charset charset = Charset.forName("ASCII");
    memory.writeCharSequence(msg, charset);
    assert msg.equals(memory.readCharSequence(length, charset));

    memory.setIndex(0, 0);
    charset = Charset.forName("UTF-8");
    memory.writeCharSequence(msg, charset);
    assert msg.equals(memory.readCharSequence(length, charset));
  }

  private void doRelease(Memory memory) {
    if (!pooled) {
      memory.release();
    }
  }
}
