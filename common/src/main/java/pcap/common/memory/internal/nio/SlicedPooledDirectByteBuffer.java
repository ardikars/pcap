package pcap.common.memory.internal.nio;

import java.nio.ByteBuffer;
import pcap.common.memory.Memory;

public class SlicedPooledDirectByteBuffer extends PooledDirectByteBuffer implements Memory.Sliced {

  private final PooledDirectByteBuffer previous;

  public SlicedPooledDirectByteBuffer(int index, int length, PooledDirectByteBuffer previous) {
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
