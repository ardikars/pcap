package pcap.common.memory.internal.nio;

import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import pcap.common.memory.Memory;
import pcap.common.memory.internal.allocator.AbstractPooledMemoryAllocator;
import pcap.common.util.Validate;

public abstract class AbstractPooledByteBuffer extends AbstractByteBuffer implements Memory.Pooled {

  private static final AtomicIntegerFieldUpdater<AbstractPooledByteBuffer> REF_CNT_UPDATER =
      AtomicIntegerFieldUpdater.newUpdater(AbstractPooledByteBuffer.class, "refCnt");

  final int id;
  AbstractPooledMemoryAllocator allocator;
  volatile int refCnt;

  AbstractPooledByteBuffer(
      int id,
      AbstractPooledMemoryAllocator allocator,
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
  public AbstractPooledByteBuffer capacity(int newCapacity) {
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
  public byte getByte(int index) {
    ensureNotInPool();
    return super.getByte(index);
  }

  @Override
  public short getShort(int index) {
    ensureNotInPool();
    return super.getShort(index);
  }

  @Override
  public short getShortLE(int index) {
    ensureNotInPool();
    return super.getShortLE(index);
  }

  @Override
  public int getInt(int index) {
    ensureNotInPool();
    return super.getInt(index);
  }

  @Override
  public int getIntLE(int index) {
    ensureNotInPool();
    return super.getIntLE(index);
  }

  @Override
  public long getLong(int index) {
    ensureNotInPool();
    return super.getLong(index);
  }

  @Override
  public long getLongLE(int index) {
    ensureNotInPool();
    return super.getLongLE(index);
  }

  @Override
  public Memory getBytes(int index, Memory dst, int dstIndex, int length) {
    ensureNotInPool();
    return super.getBytes(index, dst, dstIndex, length);
  }

  @Override
  public Memory getBytes(int index, byte[] dst, int dstIndex, int length) {
    ensureNotInPool();
    return super.getBytes(index, dst, dstIndex, length);
  }

  @Override
  public Memory setByte(int index, int value) {
    ensureNotInPool();
    return super.setByte(index, value);
  }

  @Override
  public Memory setShort(int index, int value) {
    ensureNotInPool();
    return super.setShort(index, value);
  }

  @Override
  public Memory setShortLE(int index, int value) {
    ensureNotInPool();
    return super.setShortLE(index, value);
  }

  @Override
  public Memory setInt(int index, int value) {
    ensureNotInPool();
    return super.setInt(index, value);
  }

  @Override
  public Memory setIntLE(int index, int value) {
    ensureNotInPool();
    return super.setIntLE(index, value);
  }

  @Override
  public Memory setLong(int index, long value) {
    ensureNotInPool();
    return super.setLong(index, value);
  }

  @Override
  public Memory setLongLE(int index, long value) {
    ensureNotInPool();
    return super.setLongLE(index, value);
  }

  @Override
  public Memory setBytes(int index, Memory src, int srcIndex, int length) {
    ensureNotInPool();
    return super.setBytes(index, src, srcIndex, length);
  }

  @Override
  public Memory setBytes(int index, byte[] src, int srcIndex, int length) {
    ensureNotInPool();
    return super.setBytes(index, src, srcIndex, length);
  }

  @Override
  public ByteBuffer nioBuffer() {
    ensureNotInPool();
    return super.nioBuffer();
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
    if (refCnt <= 0) {
      throw new IllegalStateException(
          String.format("This buffer has been released to the pool. ID: %d.", id()));
    }
  }
}
