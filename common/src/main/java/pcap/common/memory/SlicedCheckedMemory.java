/** This code is licenced under the GPL version 2. */
package pcap.common.memory;

import java.nio.ByteBuffer;
import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
class SlicedCheckedMemory extends CheckedMemory implements Sliced {

  private final long baseAddress;
  private final int baseCapacity;

  public SlicedCheckedMemory(
      ByteBuffer buffer,
      long baseAddress,
      int baseCapacity,
      long address,
      int capacity,
      int maxCapacity,
      int readerIndex,
      int writerIndex) {
    super(buffer, address, capacity, maxCapacity, readerIndex, writerIndex);
    this.baseAddress = baseAddress;
    this.baseCapacity = baseCapacity;
  }

  @Override
  public ByteBuffer nioBuffer() {
    if (buffer != null) {
      return buffer;
    }
    ensureAccessible(0, baseCapacity);
    return ACCESSOR.nioBuffer(baseAddress, baseCapacity);
  }

  @Override
  public void release() {
    if (!freed) {
      ACCESSOR.deallocate(baseAddress);
    }
  }

  @Override
  public Memory unslice() {
    int index = (int) (address - baseAddress);
    return new CheckedMemory(
        buffer,
        baseAddress,
        capacity + index,
        maxCapacity + index,
        readerIndex() - index,
        writerIndex() - index);
  }
}
