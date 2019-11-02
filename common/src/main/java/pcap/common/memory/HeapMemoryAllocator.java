/** This code is licenced under the GPL version 2. */
package pcap.common.memory;

import java.nio.ByteBuffer;
import pcap.common.annotation.Inclubating;
import pcap.common.internal.Unsafe;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
final class HeapMemoryAllocator implements MemoryAllocator {

  @Override
  public Memory allocate(int capacity) {
    return allocate(capacity, 0, 0, 0, true);
  }

  @Override
  public Memory allocate(int capacity, boolean checking) {
    return allocate(capacity, capacity, 0, 0, checking);
  }

  @Override
  public Memory allocate(int capacity, int maxCapacity) {
    return allocate(capacity, maxCapacity, 0, 0, true);
  }

  @Override
  public Memory allocate(int capacity, int maxCapacity, boolean checking) {
    return allocate(capacity, maxCapacity, 0, 0, checking);
  }

  @Override
  public Memory allocate(int capacity, int maxCapacity, int readerIndex, int writerIndex) {
    return allocate(capacity, maxCapacity, readerIndex, writerIndex, true);
  }

  @Override
  public Memory allocate(
      int capacity, int maxCapacity, int readerIndex, int writerIndex, boolean checking) {
    if (Unsafe.HAS_UNSAFE && MemoryAllocator.UNSAFE_BUFFER) {
      if (!checking && UNCHECKED) {
        return new UncheckedByteArray(
                0, new byte[capacity], capacity, maxCapacity, readerIndex, writerIndex);
      }
      return new CheckedByteArray(
              0, new byte[capacity], capacity, maxCapacity, readerIndex, writerIndex);
    } else {
      ByteBuffer buffer = ByteBuffer.allocate(capacity);
      Memory memory = new ByteBuf(0, buffer, capacity, maxCapacity, readerIndex, writerIndex);
      return memory;
    }
  }

  @Override
  public void close() {
    //
  }
}
