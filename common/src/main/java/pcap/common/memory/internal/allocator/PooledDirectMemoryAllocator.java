package pcap.common.memory.internal.allocator;

import java.nio.ByteBuffer;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import pcap.common.logging.Logger;
import pcap.common.logging.LoggerFactory;
import pcap.common.memory.Memory;
import pcap.common.memory.MemoryAllocator;
import pcap.common.memory.internal.nio.PooledDirectByteBuffer;
import pcap.common.util.Properties;
import pcap.common.util.Validate;

public class PooledDirectMemoryAllocator implements MemoryAllocator {

  private static final Logger LOGGER = LoggerFactory.getLogger(PooledDirectMemoryAllocator.class);

  private static final AtomicIntegerFieldUpdater<PooledDirectMemoryAllocator> ID_GERERATOR_UPDATER =
      AtomicIntegerFieldUpdater.newUpdater(PooledDirectMemoryAllocator.class, "id");

  private static final boolean ZEROING =
      Properties.getBoolean("pcap.common.memory.pool.zeroing", true);

  private final int poolSize;
  private final int maxPoolSize;
  private final int maxMemoryCapacity;
  private final Queue<Memory.Pooled> pool;

  private volatile int id = 0;

  public PooledDirectMemoryAllocator(int poolSize, int maxPoolSize, int maxMemoryCapacity) {
    this.poolSize = poolSize;
    this.maxPoolSize = maxPoolSize;
    this.maxMemoryCapacity = maxMemoryCapacity;
    this.pool = new ConcurrentLinkedQueue<>();
    for (int i = 0; i < poolSize; i++) {
      pool.offer(allocatePooledMemory(maxMemoryCapacity, 0, 0));
    }
  }

  @Override
  public Memory allocate(int capacity) {
    return allocate(capacity, capacity);
  }

  @Override
  public Memory allocate(int capacity, int maxCapacity) {
    return allocate(capacity, maxCapacity, 0, 0);
  }

  @Override
  public Memory allocate(int capacity, int maxCapacity, int readerIndex, int writerIndex) {
    Validate.notIllegalArgument(
        capacity > 0 && maxCapacity > 0,
        String.format(
            "capacity: %d, maxCapacity: %d (Required non negative value)", capacity, maxCapacity));
    Validate.notIllegalArgument(
        capacity <= maxCapacity,
        String.format(
            "capacity: %d (expected: %d <= maxCapacity(%d))", capacity, capacity, maxCapacity));
    Validate.notIllegalArgument(
        capacity <= maxMemoryCapacity && maxCapacity <= maxMemoryCapacity,
        String.format(
            "capacity: %d <= maxCapacity(%d), maxCapacity: %d <= maxMemoryCapacity(%d)",
            capacity, maxCapacity, maxCapacity, maxMemoryCapacity));
    Validate.notIllegalArgument(
        readerIndex >= 0 && writerIndex >= 0,
        String.format(
            "readerIndex: %d, writerIndex: %d (required non negative value)",
            readerIndex, writerIndex));
    final Memory.Pooled poll = pool.poll();
    if (poll != null) {
      PooledDirectByteBuffer memory = (PooledDirectByteBuffer) poll;
      memory.setIndex(readerIndex, writerIndex);
      memory.retain();
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("Allocate buffer with id %d (refCnt: %d).", memory.id(), memory.refCnt());
      }
      return memory;
    }
    if (id == maxPoolSize) {
      throw new IllegalStateException(String.format("Maximum pool reached %d", maxPoolSize));
    }
    final PooledDirectByteBuffer pooled = allocatePooledMemory(capacity, readerIndex, writerIndex);
    pooled.setIndex(readerIndex, writerIndex);
    pool.offer(pooled);
    pooled.retain();
    if (LOGGER.isDebugEnabled()) {
      LOGGER.debug("Allocate buffer with id %d (refCnt: %d).", pooled.id(), pooled.refCnt());
    }
    return pooled;
  }

  public boolean offer(PooledDirectByteBuffer buffer) {
    try {
      if (pool.size() > maxPoolSize) {
        throw new IllegalStateException(
            String.format(
                "size: %d (expected: %d < poolSize(%d))", pool.size(), pool.size(), poolSize));
      }
      pool.offer(buffer);
      return true;
    } catch (IllegalStateException e) {
      return false;
    }
  }

  private PooledDirectByteBuffer allocatePooledMemory(
      int capacity, int readerIndex, int writerIndex) {
    ByteBuffer buffer = ByteBuffer.allocateDirect(maxMemoryCapacity);
    return new PooledDirectByteBuffer(
        ID_GERERATOR_UPDATER.incrementAndGet(this),
        this,
        0,
        buffer,
        capacity,
        maxMemoryCapacity,
        readerIndex,
        writerIndex);
  }
}
