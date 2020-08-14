/** This code is licenced under the GPL version 2. */
package pcap.common.memory.internal.nio.allocator;

import java.nio.ByteBuffer;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;
import pcap.common.memory.MemoryAllocator;
import pcap.common.memory.internal.nio.HeapByteBuffer;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public final class HeapMemoryAllocator implements MemoryAllocator {

  @Override
  public String name() {
    return "NioHeapMemoryAllocator";
  }

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
    ByteBuffer buffer = ByteBuffer.allocate(capacity);
    return new HeapByteBuffer(0, buffer, capacity, maxCapacity, readerIndex, writerIndex);
  }
}
