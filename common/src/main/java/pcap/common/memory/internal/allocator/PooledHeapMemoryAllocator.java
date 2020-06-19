package pcap.common.memory.internal.allocator;

import java.lang.ref.WeakReference;
import java.nio.ByteBuffer;
import pcap.common.memory.internal.nio.AbstractPooledByteBuffer;
import pcap.common.memory.internal.nio.PooledHeapByteBuffer;

public class PooledHeapMemoryAllocator extends AbstractPooledMemoryAllocator {

  public PooledHeapMemoryAllocator(int poolSize, int maxPoolSize, int maxMemoryCapacity) {
    super(poolSize, maxPoolSize, maxMemoryCapacity);
  }

  @Override
  WeakReference<AbstractPooledByteBuffer> allocatePooledMemory(
      int capacity, int readerIndex, int writerIndex) {
    ByteBuffer buffer = ByteBuffer.allocate(maxMemoryCapacity);
    return new WeakReference<>(
        new PooledHeapByteBuffer(
            ID_GERERATOR_UPDATER.incrementAndGet(this),
            this,
            0,
            buffer,
            capacity,
            maxMemoryCapacity,
            readerIndex,
            writerIndex));
  }
}
