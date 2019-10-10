/** This code is licenced under the GPL version 2. */
package pcap.common.memory;

import java.nio.ByteBuffer;
import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
class CheckedByteArray extends UncheckedByteArray {

  public CheckedByteArray(int capacity, int maxCapacity, int readerIndex, int writerIndex) {
    this(0, null, capacity, maxCapacity, readerIndex, writerIndex);
  }

  public CheckedByteArray(
      int baseIndex,
      byte[] buffer,
      int capacity,
      int maxCapacity,
      int readerIndex,
      int writerIndex) {
    super(baseIndex, buffer, capacity, maxCapacity, readerIndex, writerIndex);
  }

  @Override
  public CheckedByteArray capacity(int newCapacity) {
    ensureAccessible();
    checkNewCapacity(newCapacity);
    this.buffer = new byte[newCapacity];
    this.capacity = newCapacity;
    this.maxCapacity = maxCapacity > newCapacity ? maxCapacity : newCapacity;
    return this;
  }

  @Override
  public byte getByte(int index) {
    ensureAccessible(index, 1);
    return super.getByte(index);
  }

  @Override
  public short getShort(int index) {
    ensureAccessible(index, 2);
    return super.getShort(index);
  }

  @Override
  public short getShortLE(int index) {
    ensureAccessible(index, 2);
    return super.getShortLE(index);
  }

  @Override
  public int getInt(int index) {
    ensureAccessible(index, 4);
    return super.getInt(index);
  }

  @Override
  public int getIntLE(int index) {
    ensureAccessible(index, 4);
    return super.getIntLE(index);
  }

  @Override
  public long getLong(int index) {
    ensureAccessible(index, 8);
    return super.getLong(index);
  }

  @Override
  public long getLongLE(int index) {
    ensureAccessible(index, 8);
    return super.getLongLE(index);
  }

  @Override
  public CheckedByteArray getBytes(int index, Memory dst, int dstIndex, int length) {
    ensureAccessible(index, length);
    super.getBytes(index, dst, dstIndex, length);
    return this;
  }

  @Override
  public CheckedByteArray getBytes(int index, byte[] dst, int dstIndex, int length) {
    ensureAccessible(index, length);
    super.getBytes(index, dst, dstIndex, length);
    return this;
  }

  @Override
  public CheckedByteArray setByte(int index, int value) {
    ensureAccessible(index, 1);
    super.setByte(index, value);
    return this;
  }

  @Override
  public CheckedByteArray setShort(int index, int value) {
    ensureAccessible(index, 2);
    super.setShort(index, value);
    return this;
  }

  @Override
  public CheckedByteArray setShortLE(int index, int value) {
    ensureAccessible(index, 2);
    super.setShortLE(index, value);
    return this;
  }

  @Override
  public CheckedByteArray setInt(int index, int value) {
    ensureAccessible(index, 4);
    super.setInt(index, value);
    return this;
  }

  @Override
  public CheckedByteArray setIntLE(int index, int value) {
    ensureAccessible(index, 4);
    super.setIntLE(index, value);
    return this;
  }

  @Override
  public CheckedByteArray setLong(int index, long value) {
    ensureAccessible(index, 8);
    super.setLong(index, value);
    return this;
  }

  @Override
  public CheckedByteArray setLongLE(int index, long value) {
    ensureAccessible(index, 8);
    super.setLongLE(index, value);
    return this;
  }

  @Override
  public CheckedByteArray setBytes(int index, Memory src, int srcIndex, int length) {
    ensureAccessible(index, length);
    super.setBytes(index, src, srcIndex, length);
    return this;
  }

  @Override
  public CheckedByteArray setBytes(int index, byte[] src, int srcIndex, int length) {
    ensureAccessible(index, length);
    super.setBytes(index, src, srcIndex, length);
    return this;
  }

  @Override
  public long memoryAddress() {
    ensureAccessible();
    return super.memoryAddress();
  }

  @Override
  public CheckedByteArray copy(int index, int length) {
    ensureAccessible(index, length);
    byte[] data = new byte[length];
    System.arraycopy(buffer, index, data, 0, length);
    return new CheckedByteArray(
        0, data, length, length < maxCapacity ? maxCapacity : length, readerIndex(), writerIndex());
  }

  @Override
  public CheckedByteArray slice(int index, int length) {
    ensureAccessible(index, length);
    return new SlicedCheckedByteArray(
        index,
        buffer,
        length,
        length < maxCapacity ? maxCapacity : length,
        readerIndex() - index,
        writerIndex() - index);
  }

  @Override
  public CheckedByteArray duplicate() {
    ensureAccessible();
    int length = buffer.length;
    byte[] data = new byte[length];
    System.arraycopy(buffer, 0, data, 0, length);
    return new CheckedByteArray(0, buffer, capacity, maxCapacity, readerIndex(), writerIndex());
  }

  @Override
  public ByteBuffer nioBuffer() {
    ensureAccessible();
    return super.nioBuffer();
  }

  void ensureAccessible() {
    if (freed) {
      // throw new IllegalStateException(String.format("%d is already freed.", address));
    }
  }

  void ensureAccessible(int index, int length) {
    if (freed) {
      // throw new IllegalStateException(String.format("%d is already freed.", address));
    }
    checkIndex(index, length);
  }
}
