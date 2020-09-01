/** This code is licenced under the GPL version 2. */
package pcap.common.memory.internal.nio.allocator;

import java.nio.ByteBuffer;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.AbstractMemoryAllocator;
import pcap.common.memory.Memory;
import pcap.common.memory.internal.nio.HeapByteBuffer;
import pcap.common.util.Validate;

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
    Validate.notIllegalArgument(
        capacity <= Integer.MAX_VALUE,
        String.format(
            "capacity: {} (excepted: capacity({}) <= {})", capacity, capacity, Integer.MAX_VALUE));
    Validate.notIllegalArgument(
        maxCapacity <= Integer.MAX_VALUE,
        String.format(
            "maxCapacity: {} (excepted: maxCapacity({}) <= {})",
            maxCapacity,
            maxCapacity,
            Integer.MAX_VALUE));
    Validate.notIllegalArgument(
        capacity <= maxCapacity,
        String.format(
            "capacity: {}, maxCapacity: {} (excepted: capacity({}) <= maxCapacity({}))",
            capacity,
            maxCapacity,
            capacity,
            maxCapacity));
    ByteBuffer buffer = ByteBuffer.allocate((int) capacity & Integer.MAX_VALUE);
    return new HeapByteBuffer(
        0,
        buffer,
        (int) capacity & Integer.MAX_VALUE,
        (int) maxCapacity & Integer.MAX_VALUE,
        (int) readerIndex & Integer.MAX_VALUE,
        (int) writerIndex & Integer.MAX_VALUE);
  }
}
