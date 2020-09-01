package pcap.common.memory.internal.nio;

import java.nio.ByteBuffer;
import pcap.common.memory.AbstractMemory;
import pcap.common.memory.Memory;
import pcap.common.util.Validate;

public abstract class AbstractByteBuffer extends AbstractMemory<ByteBuffer> {

  protected final int baseIndex;

  public AbstractByteBuffer(
      int baseIndex,
      ByteBuffer buffer,
      int capacity,
      int maxCapacity,
      int readerIndex,
      int writerIndex) {
    super(buffer, capacity, maxCapacity, readerIndex, writerIndex);
    this.baseIndex = baseIndex;
  }

  static void validateSize(long size) {
    Validate.notIllegalArgument(size <= Integer.MAX_VALUE && size >= 0);
  }

  @Override
  public Memory capacity(long newCapacityL) {
    validateSize(newCapacityL);
    int newCapacity = (int) (newCapacityL & Integer.MAX_VALUE);
    checkNewCapacity(newCapacity);
    if (newCapacity > capacity) {
      if (buffer.isDirect()) {
        buffer = ByteBuffer.allocateDirect(newCapacity);
      } else {
        buffer = ByteBuffer.allocate(newCapacity);
      }
    } else {
      buffer.limit(newCapacity);
    }
    this.capacity = newCapacity;
    return this;
  }

  @Override
  public byte getByte(long indexL) {
    validateSize(indexL);
    int index = (int) indexL & Integer.MAX_VALUE;
    return buffer.get(baseIndex + index);
  }

  @Override
  public short getShort(long indexL) {
    validateSize(indexL);
    int index = (int) indexL & Integer.MAX_VALUE;
    return buffer.getShort(baseIndex + index);
  }

  @Override
  public short getShortLE(long indexL) {
    validateSize(indexL);
    int index = (int) indexL & Integer.MAX_VALUE;
    return Short.reverseBytes(buffer.getShort(baseIndex + index));
  }

  @Override
  public int getInt(long indexL) {
    validateSize(indexL);
    int index = (int) indexL & Integer.MAX_VALUE;
    return buffer.getInt(baseIndex + index);
  }

  @Override
  public int getIntLE(long indexL) {
    validateSize(indexL);
    int index = (int) indexL & Integer.MAX_VALUE;
    return Integer.reverseBytes(buffer.getInt(baseIndex + index));
  }

  @Override
  public long getLong(long indexL) {
    validateSize(indexL);
    int index = (int) indexL & Integer.MAX_VALUE;
    return buffer.getLong(baseIndex + index);
  }

  @Override
  public long getLongLE(long indexL) {
    validateSize(indexL);
    int index = (int) indexL & Integer.MAX_VALUE;
    return Long.reverseBytes(buffer.getLong(baseIndex + index));
  }

  @Override
  public Memory getBytes(long index, Memory dst, long dstIndex, long length) {
    validateSize(index);
    validateSize(dstIndex);
    validateSize(length);
    byte[] b = new byte[(int) length & Integer.MAX_VALUE];
    getBytes(index, b, 0, length);
    dst.setBytes(dstIndex, b);
    return this;
  }

  @Override
  public Memory getBytes(long index, byte[] dst, long dstIndexL, long lengthL) {
    validateSize(index);
    validateSize(dstIndexL);
    validateSize(lengthL);
    int currectIndex = baseIndex + (int) index & Integer.MAX_VALUE;
    int dstIndex = (int) dstIndexL & Integer.MAX_VALUE;
    int length = (int) lengthL & Integer.MAX_VALUE;
    for (int i = dstIndex; i < (length + dstIndex); i++) {
      dst[i] = buffer.get(currectIndex++);
    }
    return this;
  }

  @Override
  public Memory setByte(long index, int value) {
    validateSize(index);
    buffer.put(baseIndex + (int) index & Integer.MAX_VALUE, (byte) value);
    return this;
  }

  @Override
  public Memory setShort(long index, int value) {
    validateSize(index);
    buffer.putShort(baseIndex + (int) index & Integer.MAX_VALUE, (short) value);
    return this;
  }

  @Override
  public Memory setShortLE(long index, int value) {
    validateSize(index);
    buffer.putShort(baseIndex + (int) index & Integer.MAX_VALUE, Short.reverseBytes((short) value));
    return this;
  }

  @Override
  public Memory setInt(long index, int value) {
    validateSize(index);
    buffer.putInt(baseIndex + (int) index & Integer.MAX_VALUE, value);
    return this;
  }

  @Override
  public Memory setIntLE(long index, int value) {
    validateSize(index);
    buffer.putInt(baseIndex + (int) index & Integer.MAX_VALUE, Integer.reverseBytes(value));
    return this;
  }

  @Override
  public Memory setLong(long index, long value) {
    validateSize(index);
    buffer.putLong(baseIndex + (int) index & Integer.MAX_VALUE, value);
    return this;
  }

  @Override
  public Memory setLongLE(long index, long value) {
    validateSize(index);
    buffer.putLong(baseIndex + (int) index & Integer.MAX_VALUE, Long.reverseBytes(value));
    return this;
  }

  @Override
  public Memory setBytes(long index, Memory src, long srcIndex, long length) {
    validateSize(index);
    byte[] b = new byte[(int) src.capacity() & Integer.MAX_VALUE];
    src.getBytes(0, b);
    setBytes(index, b, srcIndex, length);
    return this;
  }

  @Override
  public Memory setBytes(long index, byte[] src, long srcIndexL, long lengthL) {
    validateSize(index);
    validateSize(srcIndexL);
    validateSize(lengthL);
    int currentIndex = baseIndex + (int) index & Integer.MAX_VALUE;
    int srcIndex = (int) srcIndexL & Integer.MAX_VALUE;
    int length = (int) lengthL & Integer.MAX_VALUE;
    for (int i = srcIndex; i < (length + srcIndex); i++) {
      buffer.put(currentIndex++, src[i]);
    }
    return this;
  }

  @Override
  public ByteOrder byteOrder() {
    return buffer.order() == java.nio.ByteOrder.BIG_ENDIAN
        ? ByteOrder.BIG_ENDIAN
        : ByteOrder.LITTLE_ENDIAN;
  }

  @Override
  public Memory byteOrder(ByteOrder byteOrder) {
    if (byteOrder() == ByteOrder.LITTLE_ENDIAN && byteOrder == ByteOrder.BIG_ENDIAN) {
      buffer.order(java.nio.ByteOrder.BIG_ENDIAN);
    } else if (byteOrder() == ByteOrder.BIG_ENDIAN && byteOrder == ByteOrder.LITTLE_ENDIAN) {
      buffer.order(java.nio.ByteOrder.LITTLE_ENDIAN);
    }
    return this;
  }

  @Override
  public boolean release() {
    buffer.clear();
    return true;
  }

  @Override
  public <T> T buffer(Class<T> clazz) {
    return (T) buffer;
  }
}
