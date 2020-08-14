package pcap.common.memory;

import java.lang.ref.WeakReference;
import java.nio.ByteBuffer;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import pcap.common.logging.Logger;
import pcap.common.logging.LoggerFactory;
import pcap.common.memory.internal.nio.AbstractPooledByteBuffer;
import pcap.common.util.Validate;

public abstract class AbstractMemoryAllocator implements MemoryAllocator {

  @Override
  public Memory wrap(byte[] bytes) {
    Validate.notIllegalArgument(bytes != null, "hexStream: null (expected: non null)");
    Memory memory = allocate(bytes.length);
    memory.writeBytes(bytes);
    return memory;
  }

  @Override
  public Memory wrap(ByteBuffer bb) {
    Validate.notIllegalArgument(bb != null, "bb: null (expected: non null)");
    byte[] data = new byte[bb.capacity()];
    bb.get(data);
    Memory memory = allocate(bb.capacity());
    memory.writeBytes(data);
    return memory;
  }

  @Override
  public Memory assemble(Memory... memories) {
    Validate.notIllegalArgument(memories != null, "memories: null (expected: non null)");
    Validate.notIllegalArgument(
        memories.length > 1, "size: " + memories.length + " (expected: memories > 1)");
    int capacity = 0;
    int maxCapacity = 0;
    for (int i = 0; i < memories.length; i++) {
      capacity += memories[i].capacity();
      maxCapacity += memories[i].maxCapacity();
    }
    Memory memory = allocate(capacity, maxCapacity);
    int index = 0;
    for (int i = 0; i < memories.length; i++) {
      memory.setBytes(index, memories[i], 0, memories[i].capacity());
      index += memories[i].capacity();
    }
    return memory;
  }

  public abstract static class AbstractPooledMemoryAllocator extends AbstractMemoryAllocator {

    protected static final Logger LOGGER =
        LoggerFactory.getLogger(AbstractPooledMemoryAllocator.class);

    protected static final AtomicIntegerFieldUpdater<AbstractPooledMemoryAllocator>
        ID_GERERATOR_UPDATER =
            AtomicIntegerFieldUpdater.newUpdater(AbstractPooledMemoryAllocator.class, "id");

    protected int poolSize;
    protected int maxPoolSize;
    protected int maxMemoryCapacity;
    protected Queue<WeakReference<Memory.Pooled>> pool;

    protected volatile int id = 0;

    protected void create(int poolSize, int maxPoolSize, int maxMemoryCapacity) {
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
              "capacity: %d, maxCapacity: %d (Required non negative value)",
              capacity, maxCapacity));
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
      final WeakReference<Memory.Pooled> reference = pool.poll();
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
      final WeakReference<Memory.Pooled> weakReference =
          allocatePooledMemory(capacity, readerIndex, writerIndex);
      final Memory.Pooled pooled = weakReference.get();
      retainBuffer(pooled, capacity, writerIndex, readerIndex);
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("Allocate buffer with id {} (refCnt: {}).", pooled.id(), pooled.refCnt());
      }
      return (Memory) pooled;
    }

    public boolean offer(Memory.Pooled buffer) {
      try {
        if (pool.size() > maxPoolSize) {
          throw new IllegalStateException(
              String.format(
                  "size: %d (expected: %d < poolSize(%d))", pool.size(), pool.size(), poolSize));
        }
        ((Memory) buffer).setIndex(0, 0);
        pool.offer(new WeakReference<>(buffer));
        return true;
      } catch (IllegalStateException e) {
        return false;
      }
    }

    void retainBuffer(Memory.Pooled buffer, int capacity, int writerIndex, int readerIndex) {
      if (buffer.refCnt() == 0) {
        buffer.retain();
        ((Memory) buffer).capacity(capacity);
        ((Memory) buffer).setIndex(writerIndex, readerIndex);
      } else {
        throw new IllegalStateException(
            String.format(
                "Failed to retain buffer. RefCnt: %d, ID: %d.", buffer.refCnt(), buffer.id()));
      }
    }

    protected abstract WeakReference<Memory.Pooled> allocatePooledMemory(
        int capacity, int readerIndex, int writerIndex);
  }
}
