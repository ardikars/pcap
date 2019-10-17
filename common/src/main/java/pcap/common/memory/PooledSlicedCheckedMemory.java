/** This code is licenced under the GPL version 2. */
package pcap.common.memory;

import java.nio.ByteBuffer;
import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
class PooledSlicedCheckedMemory extends SlicedCheckedMemory implements Pooled {

  PooledSlicedCheckedMemory(
      ByteBuffer buffer,
      long baseAddress,
      int baseCapacity,
      long address,
      int capacity,
      int maxCapacity,
      int readerIndex,
      int writerIndex) {
    super(
        buffer,
        baseAddress,
        baseCapacity,
        address,
        capacity,
        maxCapacity,
        readerIndex,
        writerIndex);
  }
}
