/** This code is licenced under the GPL version 2. */
package pcap.common.memory.internal.nio;

import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;

import java.nio.ByteBuffer;

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
  public Memory copy(int index, int length) {
    byte[] b = new byte[length];
    int currentIndex = baseIndex + index;
    getBytes(currentIndex, b, 0, length);
    ByteBuffer copy = ByteBuffer.allocateDirect(length);
    copy.put(b);
    return new DirectByteBuffer(
        baseIndex, copy, capacity(), maxCapacity(), readerIndex(), writerIndex());
  }

  @Override
  public Memory slice(int index, int length) {
    if (length > capacity - index) {
      throw new IllegalArgumentException(
          String.format("length: %d (expected: length <= %d)", length, capacity - index));
    }
    return new SlicedDirectByteBuffer(index, length, this);
  }

  @Override
  public Memory duplicate() {
    return new DirectByteBuffer(
        baseIndex, buffer.duplicate(), capacity(), maxCapacity(), readerIndex(), writerIndex());
  }

  @Override
  public Long memoryAddress() {
    return 0L;
  }
}
