package pcap.common.memory.internal.nio;

import java.nio.ByteBuffer;
import pcap.common.memory.AbstractMemory;
import pcap.common.memory.Memory;

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

  @Override
  public Memory capacity(long newCapacityL) {
    int newCapacity = (int) (newCapacityL & 0x7FFFFFFF);
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
    int index = (int) indexL & 0x7FFFFFFF;
    return buffer.get(baseIndex + index);
  }

  @Override
  public short getShort(long indexL) {
    int index = (int) indexL & 0x7FFFFFFF;
    return buffer.getShort(baseIndex + index);
  }

  @Override
  public short getShortLE(long indexL) {
    int index = (int) indexL & 0x7FFFFFFF;
    return Short.reverseBytes(buffer.getShort(baseIndex + index));
  }

  @Override
  public int getInt(long indexL) {
    int index = (int) indexL & 0x7FFFFFFF;
    return buffer.getInt(baseIndex + index);
  }

  @Override
  public int getIntLE(long indexL) {
    int index = (int) indexL & 0x7FFFFFFF;
    return Integer.reverseBytes(buffer.getInt(baseIndex + index));
  }

  @Override
  public long getLong(long indexL) {
    int index = (int) indexL & 0x7FFFFFFF;
    return buffer.getLong(baseIndex + index);
  }

  @Override
  public long getLongLE(long indexL) {
    int index = (int) indexL & 0x7FFFFFFF;
    return Long.reverseBytes(buffer.getLong(baseIndex + index));
  }

  @Override
  public Memory getBytes(long index, Memory dst, long dstIndex, long length) {
    byte[] b = new byte[(int) length & 0x7FFFFFFF];
    getBytes(index, b, 0, length);
    dst.setBytes(dstIndex, b);
    return this;
  }

  @Override
  public Memory getBytes(long index, byte[] dst, long dstIndexL, long lengthL) {
    int currectIndex = baseIndex + (int) index & 0x7FFFFFFF;
    int dstIndex = (int) dstIndexL & 0x7FFFFFFF;
    int length = (int) lengthL & 0x7FFFFFFF;
    for (int i = dstIndex; i < (length + dstIndex); i++) {
      dst[i] = buffer.get(currectIndex++);
    }
    return this;
  }

  @Override
  public Memory setByte(long index, int value) {
    buffer.put(baseIndex + (int) index & 0x7FFFFFFF, (byte) value);
    return this;
  }

  @Override
  public Memory setShort(long index, int value) {
    buffer.putShort(baseIndex + (int) index & 0x7FFFFFFF, (short) value);
    return this;
  }

  @Override
  public Memory setShortLE(long index, int value) {
    buffer.putShort(baseIndex + (int) index & 0x7FFFFFFF, Short.reverseBytes((short) value));
    return this;
  }

  @Override
  public Memory setInt(long index, int value) {
    buffer.putInt(baseIndex + (int) index & 0x7FFFFFFF, value);
    return this;
  }

  @Override
  public Memory setIntLE(long index, int value) {
    buffer.putInt(baseIndex + (int) index & 0x7FFFFFFF, Integer.reverseBytes(value));
    return this;
  }

  @Override
  public Memory setLong(long index, long value) {
    buffer.putLong(baseIndex + (int) index & 0x7FFFFFFF, value);
    return this;
  }

  @Override
  public Memory setLongLE(long index, long value) {
    buffer.putLong(baseIndex + (int) index & 0x7FFFFFFF, Long.reverseBytes(value));
    return this;
  }

  @Override
  public Memory setBytes(long index, Memory src, long srcIndex, long length) {
    byte[] b = new byte[(int) src.capacity() & 0x7FFFFFFF];
    src.getBytes(0, b);
    setBytes(index, b, srcIndex, length);
    return this;
  }

  @Override
  public Memory setBytes(long index, byte[] src, long srcIndexL, long lengthL) {
    int currentIndex = baseIndex + (int) index & 0x7FFFFFFF;
    int srcIndex = (int) srcIndexL & 0x7FFFFFFF;
    int length = (int) lengthL & 0x7FFFFFFF;
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
  public ByteBuffer nioBuffer() {
    return buffer;
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
