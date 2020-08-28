/** This code is licenced under the GPL version 2. */
package pcap.common.memory.internal.nio;

import java.nio.ByteBuffer;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class DirectByteBuffer extends AbstractByteBuffer implements Memory.Direct<Long> {

  public DirectByteBuffer(
      int baseIndex,
      ByteBuffer buffer,
      int capacity,
      int maxCapacity,
      int readerIndex,
      int writerIndex) {
    super(baseIndex, buffer, capacity, maxCapacity, readerIndex, writerIndex);
  }

  @Override
  public DirectByteBuffer copy(long index, long length) {
    byte[] b = new byte[(int) length & 0x7FFFFFFF];
    int currentIndex = baseIndex + (int) index & 0x7FFFFFFF;
    getBytes(currentIndex, b, 0, length);
    ByteBuffer copy = ByteBuffer.allocateDirect(b.length);
    copy.put(b);
    return new DirectByteBuffer(
        baseIndex,
        copy,
        (int) capacity(),
        (int) maxCapacity(),
        (int) readerIndex(),
        (int) writerIndex());
  }

  @Override
  public DirectByteBuffer slice(long index, long length) {
    if (length > capacity - index) {
      throw new IllegalArgumentException(
          String.format("length: %d (expected: length <= %d)", length, capacity - index));
    }
    return new SlicedDirectByteBuffer((int) index & 0x7FFFFFFF, (int) length & 0x7FFFFFFF, this);
  }

  @Override
  public DirectByteBuffer duplicate() {
    return new DirectByteBuffer(
        baseIndex,
        buffer.duplicate(),
        (int) capacity(),
        (int) maxCapacity(),
        (int) readerIndex(),
        (int) writerIndex());
  }

  @Override
  public Long memoryAddress() {
    return 0L;
  }

  public static class SlicedDirectByteBuffer extends DirectByteBuffer implements Memory.Sliced {

    final AbstractByteBuffer previous;

    public SlicedDirectByteBuffer(int index, int length, AbstractByteBuffer previous) {
      super(
          previous.baseIndex + index,
          previous.buffer(ByteBuffer.class).duplicate(),
          length,
          previous.maxCapacity() - index < 0 ? 0 : (int) previous.maxCapacity() - index,
          previous.readerIndex() - index < 0 ? 0 : (int) previous.readerIndex() - index,
          previous.writerIndex() - index < 0 ? 0 : (int) previous.writerIndex() - index);
      this.previous = previous;
    }

    @Override
    public SlicedDirectByteBuffer duplicate() {
      return new SlicedDirectByteBuffer(baseIndex - previous.baseIndex, (int) capacity, previous);
    }

    @Override
    public Memory unSlice() {
      return previous;
    }
  }
}
