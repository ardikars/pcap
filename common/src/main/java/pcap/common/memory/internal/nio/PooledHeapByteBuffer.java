package pcap.common.memory.internal.nio;

import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import pcap.common.memory.Memory;
import pcap.common.memory.internal.allocator.PooledHeapMemoryAllocator;

public class PooledHeapByteBuffer extends HeapByteBuffer implements Memory.Pooled {

  private static final AtomicIntegerFieldUpdater<PooledHeapByteBuffer> REF_CNT_UPDATER =
      AtomicIntegerFieldUpdater.newUpdater(PooledHeapByteBuffer.class, "refCnt");

  final PooledHeapMemoryAllocator allocator;
  private final int id;
  private volatile int refCnt;

  public PooledHeapByteBuffer(
      int id,
      PooledHeapMemoryAllocator allocator,
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
  public boolean release() {
    if (refCnt() - 1 != 0) {
      throw new IllegalStateException(
          String.format("There is an object using this object as reference."));
    }
    REF_CNT_UPDATER.decrementAndGet(this);
    setIndex(0, 0);
    return allocator.offer(this);
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
}
