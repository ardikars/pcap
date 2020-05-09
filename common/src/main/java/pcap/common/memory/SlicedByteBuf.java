/** This code is licenced under the GPL version 2. */
package pcap.common.memory;

import java.nio.ByteBuffer;
import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class SlicedByteBuf extends ByteBuf implements Sliced {

  SlicedByteBuf(int capacity, int maxCapacity) {
    this(capacity, maxCapacity, 0, 0);
  }

  SlicedByteBuf(int capacity, int maxCapacity, int readerIndex, int writerIndex) {
    this(0, null, capacity, maxCapacity, readerIndex, writerIndex);
  }

  SlicedByteBuf(
      int baseIndex,
      ByteBuffer buffer,
      int capacity,
      int maxCapacity,
      int readerIndex,
      int writerIndex) {
    super(baseIndex, buffer, capacity, maxCapacity, readerIndex, writerIndex);
  }

  @Override
  public long memoryAddress() {
    long address = super.memoryAddress();
    return address != 0 ? address + baseIndex : address;
  }

  @Override
  public Memory unslice() {
    return new ByteBuf(
        0,
        buffer,
        capacity + baseIndex,
        maxCapacity + baseIndex,
        readerIndex() - baseIndex,
        writerIndex() - baseIndex);
  }
}
