package pcap.common.memory.internal.nio.allocator;

import java.lang.ref.WeakReference;
import java.nio.ByteBuffer;
import pcap.common.memory.AbstractMemoryAllocator;
import pcap.common.memory.Memory;
import pcap.common.memory.internal.nio.PooledDirectByteBuffer;
import pcap.common.util.Validate;

public final class PooledDirectByteBufferAllocator
    extends AbstractMemoryAllocator.AbstractPooledMemoryAllocator {

  @Override
  public String name() {
    return "NioPooledDirectMemoryAllocator";
  }

  @Override
  protected WeakReference<Memory.Pooled> allocatePooledMemory(
      long capacity, long readerIndex, long writerIndex) {
    Validate.notIllegalArgument(
        capacity <= Integer.MAX_VALUE,
        String.format(
            "capacity: {} (excepted: capacity({}) <= {})", capacity, capacity, Integer.MAX_VALUE));
    Validate.notIllegalArgument(
        readerIndex <= Integer.MAX_VALUE && readerIndex <= capacity,
        String.format(
            "readerIndex: {}, capacity: {} (excepted: readerIndex({}) <= {} and readerIndex({}) <= capacity({}))",
            readerIndex,
            capacity,
            readerIndex,
            Integer.MAX_VALUE,
            readerIndex,
            Integer.MAX_VALUE));
    Validate.notIllegalArgument(
        writerIndex <= Integer.MAX_VALUE && writerIndex <= capacity,
        String.format(
            "writerIndex: {}, capacity: {} (excepted: writerIndex({}) <= {} and writerIndex({}) <= capacity({}))",
            writerIndex,
            capacity,
            writerIndex,
            Integer.MAX_VALUE,
            writerIndex,
            Integer.MAX_VALUE));
    ByteBuffer buffer = ByteBuffer.allocateDirect((int) maxMemoryCapacity & Integer.MAX_VALUE);

    Memory.Pooled pooled =
        new PooledDirectByteBuffer(
            ID_GERERATOR_UPDATER.incrementAndGet(this),
            this,
            0,
            buffer,
            (int) capacity & Integer.MAX_VALUE,
            (int) maxMemoryCapacity & Integer.MAX_VALUE,
            (int) readerIndex & Integer.MAX_VALUE,
            (int) writerIndex & Integer.MAX_VALUE);
    return new WeakReference<>(pooled);
  }
}
