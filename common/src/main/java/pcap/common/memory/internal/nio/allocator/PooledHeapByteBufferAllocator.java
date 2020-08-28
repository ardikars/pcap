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
      long capacity, long readerIndex, long writerIndex) {
    ByteBuffer buffer = ByteBuffer.allocate((int) maxMemoryCapacity & 0x7FFFFFFF);
    return new WeakReference<>(
        new PooledHeapByteBuffer(
            ID_GERERATOR_UPDATER.incrementAndGet(this),
            this,
            0,
            buffer,
            (int) capacity & 0x7FFFFFFF,
            (int) maxMemoryCapacity & 0x7FFFFFFF,
            (int) readerIndex & 0x7FFFFFFF,
            (int) writerIndex & 0x7FFFFFFF));
  }
}
