/** This code is licenced under the GPL version 2. */
package pcap.common.memory;

import java.nio.ByteBuffer;
import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
class PooledSlicedByteBuf extends PooledByteBuf {

  PooledSlicedByteBuf(int capacity, int maxCapacity) {
    super(capacity, maxCapacity);
  }

  PooledSlicedByteBuf(int capacity, int maxCapacity, int readerIndex, int writerIndex) {
    super(capacity, maxCapacity, readerIndex, writerIndex);
  }

  PooledSlicedByteBuf(
      int baseIndex,
      ByteBuffer buffer,
      int capacity,
      int maxCapacity,
      int readerIndex,
      int writerIndex) {
    super(baseIndex, buffer, capacity, maxCapacity, readerIndex, writerIndex);
  }
}
