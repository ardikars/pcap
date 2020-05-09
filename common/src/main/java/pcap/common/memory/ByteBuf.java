/** This code is licenced under the GPL version 2. */
package pcap.common.memory;

import pcap.common.annotation.Inclubating;

import java.nio.ByteBuffer;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class ByteBuf extends AbstractMemory<ByteBuffer> {

  final int baseIndex;

  ByteBuf(int capacity, int maxCapacity) {
    this(capacity, maxCapacity, 0, 0);
  }

  ByteBuf(int capacity, int maxCapacity, int readerIndex, int writerIndex) {
    this(0, null, capacity, maxCapacity, readerIndex, writerIndex);
  }

  ByteBuf(
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
  public Memory capacity(int newCapacity) {
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
  public byte getByte(int index) {
    return buffer.get(baseIndex + index);
  }

  @Override
  public short getShort(int index) {
    return buffer.getShort(baseIndex + index);
  }

  @Override
  public short getShortLE(int index) {
    return Short.reverseBytes(buffer.getShort(baseIndex + index));
  }

  @Override
  public int getInt(int index) {
    return buffer.getInt(baseIndex + index);
  }

  @Override
  public int getIntLE(int index) {
    return Integer.reverseBytes(buffer.getInt(baseIndex + index));
  }

  @Override
  public long getLong(int index) {
    return buffer.getLong(baseIndex + index);
  }

  @Override
  public long getLongLE(int index) {
    return Long.reverseBytes(buffer.getLong(baseIndex + index));
  }

  @Override
  public Memory getBytes(int index, Memory dst, int dstIndex, int length) {
    byte[] b = new byte[length];
    getBytes(index, b, 0, length);
    dst.setBytes(dstIndex, b);
    return this;
  }

  @Override
  public Memory getBytes(int index, byte[] dst, int dstIndex, int length) {
    int currectIndex = baseIndex + index;
    for (int i = dstIndex; i < (length + dstIndex); i++) {
      dst[i] = buffer.get(currectIndex++);
    }
    return this;
  }

  @Override
  public Memory setByte(int index, int value) {
    buffer.put(baseIndex + index, (byte) value);
    return this;
  }

  @Override
  public Memory setShort(int index, int value) {
    buffer.putShort(baseIndex + index, (short) value);
    return this;
  }

  @Override
  public Memory setShortLE(int index, int value) {
    buffer.putShort(baseIndex + index, Short.reverseBytes((short) value));
    return this;
  }

  @Override
  public Memory setInt(int index, int value) {
    buffer.putInt(baseIndex + index, value);
    return this;
  }

  @Override
  public Memory setIntLE(int index, int value) {
    buffer.putInt(baseIndex + index, Integer.reverseBytes(value));
    return this;
  }

  @Override
  public Memory setLong(int index, long value) {
    buffer.putLong(baseIndex + index, value);
    return this;
  }

  @Override
  public Memory setLongLE(int index, long value) {
    buffer.putLong(baseIndex + index, Long.reverseBytes(value));
    return this;
  }

  @Override
  public Memory setBytes(int index, Memory src, int srcIndex, int length) {
    byte[] b = new byte[src.capacity()];
    src.getBytes(0, b);
    setBytes(index, b, srcIndex, length);
    return this;
  }

  @Override
  public Memory setBytes(int index, byte[] src, int srcIndex, int length) {
    int currentIndex = baseIndex + index;
    for (int i = srcIndex; i < (length + srcIndex); i++) {
      buffer.put(currentIndex++, src[i]);
    }
    return this;
  }

  @Override
  public Memory copy(int index, int length) {
    byte[] b = new byte[length];
    int currentIndex = baseIndex + index;
    getBytes(currentIndex, b, 0, length);
    ByteBuffer copy = ByteBuffer.allocateDirect(length);
    copy.put(b);
    return new ByteBuf(baseIndex, copy, capacity(), maxCapacity(), readerIndex(), writerIndex());
  }

  @Override
  public Memory slice(int index, int length) {
    ByteBuf duplicated =
        new SlicedByteBuf(
            baseIndex + index,
            buffer.duplicate(),
            length,
            maxCapacity(),
            readerIndex() - index,
            writerIndex() - index);
    return duplicated;
  }

  @Override
  public Memory duplicate() {
    return new ByteBuf(
        baseIndex, buffer.duplicate(), capacity(), maxCapacity(), readerIndex(), writerIndex());
  }

  @Override
  public ByteBuffer nioBuffer() {
    return buffer;
  }

  @Override
  public boolean isDirect() {
    return buffer.isDirect();
  }

  @Override
  public long memoryAddress() {
    return 0;
  }

  @Override
  public void release() {
    //
  }
}
