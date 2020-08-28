/** This code is licenced under the GPL version 2. */
package pcap.common.memory.internal.nio.allocator;

import java.nio.ByteBuffer;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.AbstractMemoryAllocator;
import pcap.common.memory.Memory;
import pcap.common.memory.internal.nio.HeapByteBuffer;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public final class HeapMemoryAllocator extends AbstractMemoryAllocator {

  @Override
  public String name() {
    return "NioHeapMemoryAllocator";
  }

  @Override
  public Memory allocate(long capacity) {
    return allocate(capacity, capacity);
  }

  @Override
  public Memory allocate(long capacity, long maxCapacity) {
    return allocate(capacity, maxCapacity, 0, 0);
  }

  @Override
  public Memory allocate(long capacity, long maxCapacity, long readerIndex, long writerIndex) {
    ByteBuffer buffer = ByteBuffer.allocate((int) capacity & 0x7FFFFFFF);
    return new HeapByteBuffer(
        0,
        buffer,
        (int) capacity & 0x7FFFFFFF,
        (int) maxCapacity & 0x7FFFFFFF,
        (int) readerIndex & 0x7FFFFFFF,
        (int) writerIndex & 0x7FFFFFFF);
  }
}
