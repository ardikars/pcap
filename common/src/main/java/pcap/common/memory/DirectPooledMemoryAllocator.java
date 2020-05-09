/** This code is licenced under the GPL version 2. */
package pcap.common.memory;

import java.nio.ByteBuffer;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;
import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
final class DirectPooledMemoryAllocator implements MemoryAllocator {

  private final int poolSize;
  private final int maxMemoryCapacity;

  private final AtomicInteger moreMemoryCounter;

  DirectPooledMemoryAllocator(MemoryAllocator memoryAllocator, int maxMemoryCapacity) {
    this(
        Math.max(Runtime.getRuntime().availableProcessors(), 15),
        Math.max(Runtime.getRuntime().availableProcessors() * 2, 15),
        maxMemoryCapacity);
  }

  DirectPooledMemoryAllocator(int poolSize, int maxPoolSize, int maxMemoryCapacity) {
    this.poolSize = poolSize;
    this.maxMemoryCapacity = maxMemoryCapacity;
    this.moreMemoryCounter = new AtomicInteger(maxPoolSize - poolSize);
    Queue<PooledMemory> queue = new ConcurrentLinkedQueue<PooledMemory>();
    for (int i = 0; i < poolSize; i++) {
      Memory memory = doAllocateForPooledMemory(maxMemoryCapacity, maxMemoryCapacity, 0, 0);
      queue.offer(new PooledMemory(memory));
    }
    Memories.POOLS.put(maxMemoryCapacity, queue);
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
          Memory newMemory = doAllocateForPooledMemory(maxMemoryCapacity, maxMemoryCapacity, 0, 0);
          Memories.offer(newMemory);
          moreMemoryCounter.decrementAndGet();
        }
      } else {
        if (moreMemoryCounter.get() == 0) {
          // allocate non pooled buffer
          Memory newMemory = doAllocateForPooledMemory(maxMemoryCapacity, maxMemoryCapacity, 0, 0);
          return newMemory;
        }
        while (moreMemoryCounter.get() > 0) {
          Memory newMemory = doAllocateForPooledMemory(maxMemoryCapacity, maxMemoryCapacity, 0, 0);
          Memories.offer(newMemory);
          moreMemoryCounter.decrementAndGet();
        }
      }
    }
    return Memories.poll(maxMemoryCapacity).capacity(capacity);
  }

  @Override
  public void close() {}

  private Memory doAllocateForPooledMemory(
      int capacity, int maxCapacity, int readerIndex, int writerIndex) {
    ByteBuffer buffer = ByteBuffer.allocateDirect(capacity);
    return new PooledByteBuf(0, buffer, capacity, maxCapacity, readerIndex, writerIndex);
  }
}
