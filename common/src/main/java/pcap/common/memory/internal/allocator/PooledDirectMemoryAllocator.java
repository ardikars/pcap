package pcap.common.memory.internal.allocator;

import java.lang.ref.WeakReference;
import java.nio.ByteBuffer;
import pcap.common.memory.internal.nio.AbstractPooledByteBuffer;
import pcap.common.memory.internal.nio.PooledDirectByteBuffer;

public class PooledDirectMemoryAllocator extends AbstractPooledMemoryAllocator {

  public PooledDirectMemoryAllocator(int poolSize, int maxPoolSize, int maxMemoryCapacity) {
    super(poolSize, maxPoolSize, maxMemoryCapacity);
  }

  @Override
  WeakReference<AbstractPooledByteBuffer> allocatePooledMemory(
      int capacity, int readerIndex, int writerIndex) {
    ByteBuffer buffer = ByteBuffer.allocateDirect(maxMemoryCapacity);
    return new WeakReference<>(
        new PooledDirectByteBuffer(
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
