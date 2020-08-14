package pcap.common.memory.internal.nio.allocator;

import java.lang.ref.WeakReference;
import java.nio.ByteBuffer;
import pcap.common.memory.AbstractMemoryAllocator;
import pcap.common.memory.Memory;
import pcap.common.memory.internal.nio.PooledHeapByteBuffer;

public final class PooledHeapByteBufferAllocator
    extends AbstractMemoryAllocator.AbstractPooledMemoryAllocator {

  @Override
  public String name() {
    return "NioPooledHeapMemoryAllocator";
  }

  @Override
  protected WeakReference<Memory.Pooled> allocatePooledMemory(
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
