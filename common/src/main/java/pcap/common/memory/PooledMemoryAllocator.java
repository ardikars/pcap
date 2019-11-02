/** This code is licenced under the GPL version 2. */
package pcap.common.memory;

import java.nio.ByteBuffer;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;
import pcap.common.annotation.Inclubating;
import pcap.common.internal.Unsafe;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
final class PooledMemoryAllocator implements MemoryAllocator {

  private final int poolSize;
  private final int maxMemoryCapacity;

  private final AtomicInteger moreMemoryCounter;

  PooledMemoryAllocator(int maxMemoryCapacity) {
    this(
        Math.max(Runtime.getRuntime().availableProcessors(), 15),
        Math.max(Runtime.getRuntime().availableProcessors() * 2, 15),
        maxMemoryCapacity);
  }

  PooledMemoryAllocator(int poolSize, int maxPoolSize, int maxMemoryCapacity) {
    this.poolSize = poolSize;
    this.maxMemoryCapacity = maxMemoryCapacity;
    this.moreMemoryCounter = new AtomicInteger(maxPoolSize - poolSize);
    Queue<PooledMemory> queue = new ConcurrentLinkedQueue<PooledMemory>();
    for (int i = 0; i < poolSize; i++) {
      Memory memory = doAllocateForPooledMemory(maxMemoryCapacity, maxMemoryCapacity, 0, 0, false);
      queue.offer(new PooledMemory(memory));
    }
    Memories.POOLS.put(maxMemoryCapacity, queue);
  }

  @Override
  public Memory allocate(int capacity) {
    return allocate(capacity, capacity);
  }

  @Override
  public Memory allocate(int capacity, boolean checking) {
    return allocate(capacity, capacity, false);
  }

  @Override
  public Memory allocate(int capacity, int maxCapacity) {
    return allocate(capacity, maxCapacity, false);
  }

  @Override
  public Memory allocate(int capacity, int maxCapacity, boolean checking) {
    return allocate(capacity, maxCapacity, 0, 0, false);
  }

  @Override
  public Memory allocate(int capacity, int maxCapacity, int readerIndex, int writerIndex) {
    return allocate(capacity, maxCapacity, readerIndex, writerIndex, false);
  }

  @Override
  public Memory allocate(
      int capacity, int maxCapacity, int readerIndex, int writerIndex, boolean checking) {
    if (capacity > maxMemoryCapacity) {
      throw new IllegalArgumentException(
          String.format("capacity: %d <= %d", capacity, maxMemoryCapacity));
    }
    if (maxCapacity > maxMemoryCapacity) {
      throw new IllegalArgumentException(
          String.format("maxCapacity: %d <= %d", capacity, maxMemoryCapacity));
    }
    Memory memory = Memories.poll(maxMemoryCapacity);
    if (memory != null) {
      memory.setIndex(readerIndex, writerIndex);
      return memory.capacity(capacity);
    } else {
      if (moreMemoryCounter.get() > poolSize) {
        for (int i = 0; i < poolSize; i++) {
          Memory newMemory =
              doAllocateForPooledMemory(maxMemoryCapacity, maxMemoryCapacity, 0, 0, checking);
          Memories.offer(newMemory);
          moreMemoryCounter.decrementAndGet();
        }
      } else {
        if (moreMemoryCounter.get() == 0) {
          // allocate non pooled buffer
          if (Unsafe.HAS_UNSAFE) {
            long address = AbstractMemory.ACCESSOR.allocate(capacity);
            if (!checking && UNCHECKED) {
              return new UncheckedMemory(address, capacity, maxCapacity, readerIndex, writerIndex);
            }
            return new CheckedMemory(address, capacity, maxCapacity, readerIndex, writerIndex);
          } else {
            ByteBuffer buffer = ByteBuffer.allocateDirect(capacity);
            return new ByteBuf(0, buffer, capacity, maxCapacity, readerIndex, writerIndex);
          }
        }
        while (moreMemoryCounter.get() > 0) {
          Memory newMemory =
              doAllocateForPooledMemory(maxMemoryCapacity, maxMemoryCapacity, 0, 0, checking);
          Memories.offer(newMemory);
          moreMemoryCounter.decrementAndGet();
        }
      }
    }
    return Memories.poll(maxMemoryCapacity).capacity(capacity);
  }

  @Override
  public void close() {
    Queue<PooledMemory> queue = Memories.POOLS.get(maxMemoryCapacity);
    PooledMemory pooledMemory;
    if (Unsafe.HAS_UNSAFE) {
      while ((pooledMemory = queue.poll()) != null) {
        AbstractMemory.ACCESSOR.deallocate(pooledMemory.get().memoryAddress());
      }
    } else {
      while ((pooledMemory = queue.poll()) != null) {
        // do nothing
      }
    }
  }

  private Memory doAllocateForPooledMemory(
      int capacity, int maxCapacity, int readerIndex, int writerIndex, boolean checking) {
    if (Unsafe.HAS_UNSAFE) {
      long address = AbstractMemory.ACCESSOR.allocate(capacity);
      if (!checking && UNCHECKED) {
        return new PooledUncheckedMemory(address, capacity, capacity, readerIndex, writerIndex);
      }
      return new PooledCheckedMemory(address, capacity, maxCapacity, readerIndex, writerIndex);
    } else {
      ByteBuffer buffer = ByteBuffer.allocateDirect(capacity);
      Memory memory = new PooledByteBuf(0, buffer, capacity, capacity, readerIndex, writerIndex);
      return memory;
    }
  }
}
