/** This code is licenced under the GPL version 2. */
package pcap.common.memory.internal.nio;

import java.nio.ByteBuffer;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class SlicedHeapByteBuffer extends HeapByteBuffer implements Memory.Sliced {

  final HeapByteBuffer previous;

  public SlicedHeapByteBuffer(int index, int length, HeapByteBuffer previous) {
    super(
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
