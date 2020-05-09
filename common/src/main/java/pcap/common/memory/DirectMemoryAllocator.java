/** This code is licenced under the GPL version 2. */
package pcap.common.memory;

import java.nio.ByteBuffer;
import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
final class DirectMemoryAllocator implements MemoryAllocator {

  @Override
  public Memory allocate(int capacity) {
    return allocate(capacity, capacity);
  }

  @Override
  public Memory allocate(int capacity, int maxCapacity) {
    return allocate(capacity, maxCapacity, 0, 0);
  }

  @Override
  public Memory allocate(int capacity, int maxCapacity, int readerIndex, int writerIndex) {
    ByteBuffer buffer = ByteBuffer.allocateDirect(capacity);
    Memory memory = new ByteBuf(0, buffer, capacity, maxCapacity, readerIndex, writerIndex);
    return memory;
  }

  @Override
  public void close() {
    //
  }
}
