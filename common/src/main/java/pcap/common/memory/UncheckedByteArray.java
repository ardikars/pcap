/** This code is licenced under the GPL version 2. */
package pcap.common.memory;

import java.nio.ByteBuffer;
import pcap.common.annotation.Inclubating;
import pcap.common.internal.Unsafe;
import pcap.common.memory.accessor.ByteAccessor;
import pcap.common.memory.accessor.ByteAccessors;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class UncheckedByteArray extends AbstractMemory<byte[]> {

  static final ByteAccessor ACCESSOR = Unsafe.HAS_UNSAFE ? ByteAccessors.byteAccessor() : null;

  final int baseIndex;

  UncheckedByteArray(int capacity, int maxCapacity) {
    this(capacity, maxCapacity, 0, 0);
  }

  UncheckedByteArray(int capacity, int maxCapacity, int readerIndex, int writerIndex) {
    this(0, null, capacity, maxCapacity, readerIndex, writerIndex);
  }

  UncheckedByteArray(
      int baseIndex,
      byte[] buffer,
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
    this.buffer = new byte[newCapacity];
    this.capacity = newCapacity;
    this.maxCapacity = maxCapacity > newCapacity ? maxCapacity : newCapacity;
    return this;
  }

  @Override
  public byte getByte(int index) {
    return buffer[index(index)];
  }

  @Override
  public short getShort(int index) {
    return ACCESSOR.getShort(buffer, index(index));
  }

  @Override
  public short getShortLE(int index) {
    return ACCESSOR.getShortLE(buffer, index(index));
  }

  @Override
  public int getInt(int index) {
    return ACCESSOR.getInt(buffer, index(index));
  }

  @Override
  public int getIntLE(int index) {
    return ACCESSOR.getIntLE(buffer, index(index));
  }

  @Override
  public long getLong(int index) {
    return ACCESSOR.getLong(buffer, index(index));
  }

  @Override
  public long getLongLE(int index) {
    return ACCESSOR.getLongLE(buffer, index(index));
  }

  @Override
  public UncheckedByteArray getBytes(int index, Memory dst, int dstIndex, int length) {
    dst.setBytes(dstIndex, buffer, index(index), length);
    return this;
  }

  @Override
  public UncheckedByteArray getBytes(int index, byte[] dst, int dstIndex, int length) {
    System.arraycopy(buffer, index(index), dst, dstIndex, length);
    return this;
  }

  @Override
  public UncheckedByteArray setByte(int index, int value) {
    ACCESSOR.setByte(buffer, index(index), value);
    return this;
  }

  @Override
  public UncheckedByteArray setShort(int index, int value) {
    ACCESSOR.setShort(buffer, index(index), value);
    return this;
  }

  @Override
  public UncheckedByteArray setShortLE(int index, int value) {
    ACCESSOR.setShortLE(buffer, index(index), value);
    return this;
  }

  @Override
  public UncheckedByteArray setInt(int index, int value) {
    ACCESSOR.setInt(buffer, index(index), value);
    return this;
  }

  @Override
  public UncheckedByteArray setIntLE(int index, int value) {
    ACCESSOR.setIntLE(buffer, index(index), value);
    return this;
  }

  @Override
  public UncheckedByteArray setLong(int index, long value) {
    ACCESSOR.setLong(buffer, index(index), value);
    return this;
  }

  @Override
  public UncheckedByteArray setLongLE(int index, long value) {
    ACCESSOR.setLongLE(buffer, index(index), value);
    return this;
  }

  @Override
  public UncheckedByteArray setBytes(int index, Memory src, int srcIndex, int length) {
    byte[] data = new byte[length];
    src.getBytes(srcIndex, data);
    System.arraycopy(data, 0, buffer, index(index), data.length);
    return this;
  }

  @Override
  public UncheckedByteArray setBytes(int index, byte[] src, int srcIndex, int length) {
    System.arraycopy(src, srcIndex, buffer, index(index), length);
    return this;
  }

  @Override
  public UncheckedByteArray copy(int index, int length) {
    byte[] data = new byte[length];
    System.arraycopy(buffer, index, data, 0, length);
    return new UncheckedByteArray(
        0, data, length, length < maxCapacity ? maxCapacity : length, readerIndex(), writerIndex());
  }

  @Override
  public UncheckedByteArray slice(int index, int length) {
    return new SlicedUncheckedByteArray(
        index,
        buffer,
        length,
        length < maxCapacity ? maxCapacity : length,
        readerIndex() - index,
        writerIndex() - index);
  }

  @Override
  public UncheckedByteArray duplicate() {
    byte[] data = new byte[capacity];
    System.arraycopy(buffer, 0, data, 0, capacity);
    return new UncheckedByteArray(0, buffer, capacity, maxCapacity, readerIndex(), writerIndex());
  }

  @Override
  public ByteBuffer nioBuffer() {
    return ByteBuffer.wrap(buffer);
  }

  @Override
  public boolean isDirect() {
    return false;
  }

  @Override
  public long memoryAddress() {
    return 0;
  }

  @Override
  public void release() {}

  private int index(int index) {
    return baseIndex + index;
  }
}
