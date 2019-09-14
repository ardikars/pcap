/** This code is licenced under the GPL version 2. */
package pcap.common.memory;

import java.nio.ByteBuffer;
import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
class CheckedMemory extends UncheckedMemory {

  public CheckedMemory(long address, int capacity, int maxCapacity) {
    super(address, capacity, maxCapacity);
  }

  public CheckedMemory(
      long address, int capacity, int maxCapacity, int readerIndex, int writerIndex) {
    super(address, capacity, maxCapacity, readerIndex, writerIndex);
  }

  @Override
  public CheckedMemory capacity(int newCapacity) {
    ensureAccessible();
    checkNewCapacity(newCapacity);
    this.address = ACCESSOR.reallocate(address, newCapacity);
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
  public CheckedMemory getBytes(int index, Memory dst, int dstIndex, int length) {
    ensureAccessible(index, length);
    super.getBytes(index, dst, dstIndex, length);
    return this;
  }

  @Override
  public CheckedMemory getBytes(int index, byte[] dst, int dstIndex, int length) {
    ensureAccessible(index, length);
    super.getBytes(index, dst, dstIndex, length);
    return this;
  }

  @Override
  public CheckedMemory setByte(int index, int value) {
    ensureAccessible(index, 1);
    super.setByte(index, value);
    return this;
  }

  @Override
  public CheckedMemory setShort(int index, int value) {
    ensureAccessible(index, 2);
    super.setShort(index, value);
    return this;
  }

  @Override
  public CheckedMemory setShortLE(int index, int value) {
    ensureAccessible(index, 2);
    super.setShortLE(index, value);
    return this;
  }

  @Override
  public CheckedMemory setInt(int index, int value) {
    ensureAccessible(index, 4);
    super.setInt(index, value);
    return this;
  }

  @Override
  public CheckedMemory setIntLE(int index, int value) {
    ensureAccessible(index, 4);
    super.setIntLE(index, value);
    return this;
  }

  @Override
  public CheckedMemory setLong(int index, long value) {
    ensureAccessible(index, 8);
    super.setLong(index, value);
    return this;
  }

  @Override
  public CheckedMemory setLongLE(int index, long value) {
    ensureAccessible(index, 8);
    super.setLongLE(index, value);
    return this;
  }

  @Override
  public CheckedMemory setBytes(int index, Memory src, int srcIndex, int length) {
    ensureAccessible(index, length);
    super.setBytes(index, src, srcIndex, length);
    return this;
  }

  @Override
  public CheckedMemory setBytes(int index, byte[] src, int srcIndex, int length) {
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
  public CheckedMemory copy(int index, int length) {
    ensureAccessible(index, length);
    long newAddress = ACCESSOR.allocate(length);
    CheckedMemory memory =
        new CheckedMemory(newAddress, length, maxCapacity, readerIndex(), writerIndex());
    if (length != 0) {
      memory.setBytes(0, this, index, length);
    }
    return memory;
  }

  @Override
  public CheckedMemory slice(int index, int length) {
    ensureAccessible(index, length);
    return new SlicedCheckedMemory(
        address,
        capacity,
        address + index,
        length,
        maxCapacity,
        readerIndex() - index,
        writerIndex() - index);
  }

  @Override
  public CheckedMemory duplicate() {
    ensureAccessible();
    CheckedMemory memory =
        new CheckedMemory(address, capacity, maxCapacity, readerIndex(), writerIndex());
    return memory;
  }

  @Override
  public ByteBuffer nioBuffer() {
    ensureAccessible();
    return super.nioBuffer();
  }

  void ensureAccessible() {
    if (freed) {
      throw new IllegalStateException(String.format("%d is already freed.", address));
    }
  }

  void ensureAccessible(int index, int length) {
    if (freed) {
      throw new IllegalStateException(String.format("%d is already freed.", address));
    }
    checkIndex(index, length);
  }
}
