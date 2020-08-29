package pcap.common.memory.internal.nio;

import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import pcap.common.memory.AbstractMemoryAllocator;
import pcap.common.memory.Memory;
import pcap.common.util.Validate;

public abstract class AbstractPooledByteBuffer extends AbstractByteBuffer implements Memory.Pooled {

  private static final AtomicIntegerFieldUpdater<AbstractPooledByteBuffer> REF_CNT_UPDATER =
      AtomicIntegerFieldUpdater.newUpdater(AbstractPooledByteBuffer.class, "refCnt");

  final int id;
  AbstractMemoryAllocator.AbstractPooledMemoryAllocator allocator;
  volatile int refCnt;

  AbstractPooledByteBuffer(
      int id,
      AbstractMemoryAllocator.AbstractPooledMemoryAllocator allocator,
      int baseIndex,
      ByteBuffer buffer,
      int capacity,
      int maxCapacity,
      int readerIndex,
      int writerIndex) {
    super(baseIndex, buffer, capacity, maxCapacity, readerIndex, writerIndex);
    this.allocator = allocator;
    this.id = id;
  }

  @Override
  public AbstractPooledByteBuffer capacity(long newCapacity) {
    ensureNotInPool();
    Validate.notIllegalArgument(
        newCapacity <= maxCapacity(),
        String.format(
            "newCapacity: %d (expected: newCapacity(%d) <= maxCapacity(%d))",
            newCapacity, newCapacity, maxCapacity()));
    capacity = newCapacity;
    return this;
  }

  @Override
  public byte getByte(long index) {
    ensureNotInPool();
    return super.getByte(index);
  }

  @Override
  public short getShort(long index) {
    ensureNotInPool();
    return super.getShort(index);
  }

  @Override
  public short getShortLE(long index) {
    ensureNotInPool();
    return super.getShortLE(index);
  }

  @Override
  public int getInt(long index) {
    ensureNotInPool();
    return super.getInt(index);
  }

  @Override
  public int getIntLE(long index) {
    ensureNotInPool();
    return super.getIntLE(index);
  }

  @Override
  public long getLong(long index) {
    ensureNotInPool();
    return super.getLong(index);
  }

  @Override
  public long getLongLE(long index) {
    ensureNotInPool();
    return super.getLongLE(index);
  }

  @Override
  public Memory getBytes(long index, Memory dst, long dstIndex, long length) {
    ensureNotInPool();
    return super.getBytes(index, dst, dstIndex, length);
  }

  @Override
  public Memory getBytes(long index, byte[] dst, long dstIndex, long length) {
    ensureNotInPool();
    return super.getBytes(index, dst, dstIndex, length);
  }

  @Override
  public Memory setByte(long index, int value) {
    ensureNotInPool();
    return super.setByte(index, value);
  }

  @Override
  public Memory setShort(long index, int value) {
    ensureNotInPool();
    return super.setShort(index, value);
  }

  @Override
  public Memory setShortLE(long index, int value) {
    ensureNotInPool();
    return super.setShortLE(index, value);
  }

  @Override
  public Memory setInt(long index, int value) {
    ensureNotInPool();
    return super.setInt(index, value);
  }

  @Override
  public Memory setIntLE(long index, int value) {
    ensureNotInPool();
    return super.setIntLE(index, value);
  }

  @Override
  public Memory setLong(long index, long value) {
    ensureNotInPool();
    return super.setLong(index, value);
  }

  @Override
  public Memory setLongLE(long index, long value) {
    ensureNotInPool();
    return super.setLongLE(index, value);
  }

  @Override
  public Memory setBytes(long index, Memory src, long srcIndex, long length) {
    ensureNotInPool();
    return super.setBytes(index, src, srcIndex, length);
  }

  @Override
  public Memory setBytes(long index, byte[] src, long srcIndex, long length) {
    ensureNotInPool();
    return super.setBytes(index, src, srcIndex, length);
  }

  @Override
  public <T> T buffer(Class<T> clazz) {
    ensureNotInPool();
    return super.buffer(clazz);
  }

  @Override
  public boolean release() {
    if (refCnt() - 1 > 0) {
      throw new IllegalStateException(
          String.format(
              "There is an object using this object as reference. RefCnt: %d, ID: %d.",
              refCnt(), id()));
    } else if (refCnt() - 1 < 0) {
      throw new IllegalStateException(
          String.format(
              "This buffer is already released to the pool. RefCnt: %d, ID: %d.", refCnt(), id()));
    }
    buffer.clear();
    boolean offer = allocator.offer(this);
    REF_CNT_UPDATER.decrementAndGet(this);
    return offer;
  }

  @Override
  public int id() {
    return id;
  }

  @Override
  public int refCnt() {
    return refCnt;
  }

  @Override
  public int refCnt(int cnt) {
    REF_CNT_UPDATER.set(this, refCnt - cnt);
    return refCnt;
  }

  @Override
  public int retain() {
    return retain(1);
  }

  @Override
  public int retain(int delta) {
    return REF_CNT_UPDATER.addAndGet(this, delta);
  }

  private void ensureNotInPool() {
    if (refCnt == 0) {
      throw new IllegalStateException(
          String.format("This buffer has been released to the pool. ID: %d.", id()));
    }
  }
}
