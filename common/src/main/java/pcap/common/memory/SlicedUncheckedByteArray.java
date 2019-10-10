/** This code is licenced under the GPL version 2. */
package pcap.common.memory;

import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
class SlicedUncheckedByteArray extends UncheckedByteArray {

  SlicedUncheckedByteArray(int capacity, int maxCapacity) {
    this(capacity, maxCapacity, 0, 0);
  }

  SlicedUncheckedByteArray(int capacity, int maxCapacity, int readerIndex, int writerIndex) {
    this(0, null, capacity, maxCapacity, readerIndex, writerIndex);
  }

  SlicedUncheckedByteArray(
      int baseIndex,
      byte[] buffer,
      int capacity,
      int maxCapacity,
      int readerIndex,
      int writerIndex) {
    super(baseIndex, buffer, capacity, maxCapacity, readerIndex, writerIndex);
  }
}
