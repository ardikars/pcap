package pcap.common.memory.internal.nio.allocator;

import java.lang.ref.WeakReference;
import java.nio.ByteBuffer;
import pcap.common.memory.AbstractMemoryAllocator;
import pcap.common.memory.Memory;
import pcap.common.memory.internal.nio.PooledDirectByteBuffer;

public final class PooledDirectByteBufferAllocator
    extends AbstractMemoryAllocator.AbstractPooledMemoryAllocator {

  @Override
  public String name() {
    return "NioPooledDirectMemoryAllocator";
  }

  @Override
  protected WeakReference<Memory.Pooled> allocatePooledMemory(
      long capacity, long readerIndex, long writerIndex) {
    ByteBuffer buffer = ByteBuffer.allocateDirect((int) maxMemoryCapacity & 0x7FFFFFFF);
    return new WeakReference<>(
        new PooledDirectByteBuffer(
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
