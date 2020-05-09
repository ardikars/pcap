/** This code is licenced under the GPL version 2. */
package pcap.common.memory;

import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public interface MemoryAllocator {

  Memory allocate(int capacity);

  Memory allocate(int capacity, int maxCapacity);

  Memory allocate(int capacity, int maxCapacity, int readerIndex, int writerIndex);

  void close();
}
