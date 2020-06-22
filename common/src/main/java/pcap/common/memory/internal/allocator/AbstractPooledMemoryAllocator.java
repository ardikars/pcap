package pcap.common.memory.internal.allocator;

import java.lang.ref.WeakReference;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import pcap.common.logging.Logger;
import pcap.common.logging.LoggerFactory;
import pcap.common.memory.Memory;
import pcap.common.memory.MemoryAllocator;
import pcap.common.memory.internal.nio.AbstractPooledByteBuffer;
import pcap.common.util.Properties;
import pcap.common.util.Validate;

public abstract class AbstractPooledMemoryAllocator implements MemoryAllocator {

  static final Logger LOGGER = LoggerFactory.getLogger(AbstractPooledMemoryAllocator.class);

  static final AtomicIntegerFieldUpdater<AbstractPooledMemoryAllocator> ID_GERERATOR_UPDATER =
      AtomicIntegerFieldUpdater.newUpdater(AbstractPooledMemoryAllocator.class, "id");

  static final boolean ZEROING = Properties.getBoolean("pcap.common.memory.pool.zeroing", true);

  final int poolSize;
  final int maxPoolSize;
  final int maxMemoryCapacity;
  final Queue<WeakReference<AbstractPooledByteBuffer>> pool;

  volatile int id = 0;

  AbstractPooledMemoryAllocator(int poolSize, int maxPoolSize, int maxMemoryCapacity) {
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
    final WeakReference<AbstractPooledByteBuffer> reference = pool.poll();
    if (reference != null) {
      Memory.Pooled poll = reference.get();
      if (poll != null) {
        AbstractPooledByteBuffer memory = (AbstractPooledByteBuffer) poll;
        retainBuffer(memory, capacity, writerIndex, readerIndex);
        if (LOGGER.isDebugEnabled()) {
          LOGGER.debug(
              "Allocate buffer with id {} (refCnt: {}) from pool.", memory.id(), memory.refCnt());
        }
        return memory;
      }
    }
    if (id == maxPoolSize) {
      throw new IllegalStateException(String.format("Maximum pool reached %d", maxPoolSize));
    }
    final WeakReference<AbstractPooledByteBuffer> weakReference =
        allocatePooledMemory(capacity, readerIndex, writerIndex);
    final AbstractPooledByteBuffer pooled = weakReference.get();
    retainBuffer(pooled, capacity, writerIndex, readerIndex);
    if (LOGGER.isDebugEnabled()) {
      LOGGER.debug("Allocate buffer with id {} (refCnt: {}).", pooled.id(), pooled.refCnt());
    }
    return pooled;
  }

  public boolean offer(AbstractPooledByteBuffer buffer) {
    try {
      if (pool.size() > maxPoolSize) {
        throw new IllegalStateException(
            String.format(
                "size: %d (expected: %d < poolSize(%d))", pool.size(), pool.size(), poolSize));
      }
      if (ZEROING) {
        buffer.capacity(maxMemoryCapacity);
        buffer.setIndex(0, 0);
        int writableBytes = buffer.writableBytes();
        while (writableBytes >= 4) {
          buffer.writeInt(0);
          writableBytes = buffer.writableBytes();
        }
        while (writableBytes > 1) {
          buffer.writeByte(0);
          writableBytes = buffer.writableBytes();
        }
      }
      buffer.setIndex(0, 0);
      pool.offer(new WeakReference<>(buffer));
      return true;
    } catch (IllegalStateException e) {
      return false;
    }
  }

  void retainBuffer(
      AbstractPooledByteBuffer buffer, int capacity, int writerIndex, int readerIndex) {
    if (buffer.refCnt() == 0) {
      buffer.retain();
      buffer.capacity(capacity);
      buffer.setIndex(writerIndex, readerIndex);
    } else {
      throw new IllegalStateException(
          String.format(
              "Failed to retain buffer. RefCnt: %d, ID: %d.", buffer.refCnt(), buffer.id()));
    }
  }

  abstract WeakReference<AbstractPooledByteBuffer> allocatePooledMemory(
      int capacity, int readerIndex, int writerIndex);
}
