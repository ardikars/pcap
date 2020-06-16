package pcap.common.memory.internal.nio;

import java.nio.ByteBuffer;
import pcap.common.memory.Memory;

public class SlicedPooledHeapByteBuffer extends PooledHeapByteBuffer implements Memory.Sliced {

  private final PooledHeapByteBuffer previous;

  public SlicedPooledHeapByteBuffer(int index, int length, PooledHeapByteBuffer previous) {
    super(
        previous.id(),
        previous.allocator,
        previous.baseIndex + index,
        previous.buffer(ByteBuffer.class).duplicate(),
        length,
        previous.maxCapacity() - index < 0 ? 0 : previous.maxCapacity() - index,
        previous.readerIndex() - index < 0 ? 0 : previous.readerIndex() - index,
        previous.writerIndex() - index < 0 ? 0 : previous.writerIndex() - index);
    this.previous = previous;
  }

  @Override
  public Memory unSlice() {
    return previous;
  }
}
