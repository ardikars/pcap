/** This code is licenced under the GPL version 2. */
package pcap.common.memory;

import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
class SlicedCheckedStream extends CheckedStream implements Sliced {

  public SlicedCheckedStream(
      int baseIndex,
      Memory[] buffer,
      int capacity,
      int maxCapacity,
      int readerIndex,
      int writerIndex) {
    super(baseIndex, buffer, capacity, maxCapacity, readerIndex, writerIndex);
  }

  @Override
  public Memory unslice() {
    return new CheckedStream(
        0,
        buffer,
        capacity + baseIndex,
        maxCapacity + baseIndex,
        readerIndex() - baseIndex,
        writerIndex() - baseIndex);
  }
}
