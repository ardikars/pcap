package pcap.common.memory.internal.nio;

import java.nio.ByteBuffer;
import pcap.common.memory.AbstractMemoryAllocator;
import pcap.common.memory.Memory;

public class PooledHeapByteBuffer extends AbstractPooledByteBuffer {

  public PooledHeapByteBuffer(
      int id,
      AbstractMemoryAllocator.AbstractPooledMemoryAllocator allocator,
      int baseIndex,
      ByteBuffer buffer,
      int capacity,
      int maxCapacity,
      int readerIndex,
      int writerIndex) {
    super(id, allocator, baseIndex, buffer, capacity, maxCapacity, readerIndex, writerIndex);
  }

  @Override
  public Memory copy(long index, long length) {
    byte[] b = new byte[(int) length & 0x7FFFFFFF];
    int currentIndex = baseIndex + (int) index & 0x7FFFFFFF;
    getBytes(currentIndex, b, 0, length);
    ByteBuffer copy = ByteBuffer.allocate(b.length);
    copy.put(b);
    return new PooledHeapByteBuffer(
        id(),
        allocator,
        baseIndex,
        copy,
        (int) capacity(),
        (int) maxCapacity(),
        (int) readerIndex(),
        (int) writerIndex());
  }

  @Override
  public Memory slice(long index, long length) {
    if (length > capacity - index) {
      throw new IllegalArgumentException(
          String.format("length: %d (expected: length <= %d)", length, capacity - index));
    }
    return new SlicedPooledHeapByteBuffer(
        (int) index & 0x7FFFFFFF, (int) length & 0x7FFFFFFF, this);
  }

  @Override
  public Memory duplicate() {
    return new PooledHeapByteBuffer(
        id(),
        allocator,
        baseIndex,
        buffer.duplicate(),
        (int) capacity(),
        (int) maxCapacity(),
        (int) readerIndex(),
        (int) writerIndex());
  }

  public static class SlicedPooledHeapByteBuffer extends PooledHeapByteBuffer
      implements Memory.Sliced {

    private final PooledHeapByteBuffer previous;

    public SlicedPooledHeapByteBuffer(int index, int length, PooledHeapByteBuffer previous) {
      super(
          previous.id(),
          previous.allocator,
          previous.baseIndex + index,
          previous.buffer(ByteBuffer.class).duplicate(),
          length,
          previous.maxCapacity() - index < 0 ? 0 : (int) previous.maxCapacity() - index,
          previous.readerIndex() - index < 0 ? 0 : (int) previous.readerIndex() - index,
          previous.writerIndex() - index < 0 ? 0 : (int) previous.writerIndex() - index);
      this.refCnt = previous.refCnt;
      this.previous = previous;
    }

    @Override
    public Memory copy(long index, long length) {
      byte[] b = new byte[(int) length & 0x7FFFFFFF];
      int currentIndex = baseIndex + (int) index & 0x7FFFFFFF;
      getBytes(currentIndex, b, 0, length);
      ByteBuffer copy = ByteBuffer.allocate(b.length);
      copy.put(b);
      return new HeapByteBuffer(
          baseIndex,
          copy,
          (int) capacity(),
          (int) maxCapacity(),
          (int) readerIndex(),
          (int) writerIndex());
    }

    @Override
    public Memory duplicate() {
      throw new UnsupportedOperationException("Duplicating heap pooled buffer is unsupported.");
    }

    @Override
    public Memory unSlice() {
      return previous;
    }
  }
}
