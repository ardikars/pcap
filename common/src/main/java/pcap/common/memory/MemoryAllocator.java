/** This code is licenced under the GPL version 2. */
package pcap.common.memory;

import pcap.common.annotation.Inclubating;
import pcap.common.internal.UnsafeHelper;
import pcap.common.util.Platforms;
import pcap.common.util.Properties;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public interface MemoryAllocator {

  boolean UNSAFE_BUFFER =
      Properties.getBoolean("pcap.unsafe", false)
          && !Platforms.isAndroid()
          && UnsafeHelper.isUnsafeAvailable();

  boolean UNCHECKED = Properties.getBoolean("pcap.unchecked", false);

  Memory allocate(int capacity);

  Memory allocate(int capacity, boolean checking);

  Memory allocate(int capacity, int maxCapacity);

  Memory allocate(int capacity, int maxCapacity, boolean checking);

  Memory allocate(int capacity, int maxCapacity, int readerIndex, int writerIndex);

  Memory allocate(
      int capacity, int maxCapacity, int readerIndex, int writerIndex, boolean checking);

  void close();
}
