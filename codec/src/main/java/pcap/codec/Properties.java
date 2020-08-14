/** This code is licenced under the GPL version 2. */
package pcap.codec;

import pcap.common.annotation.Inclubating;
import pcap.common.memory.MemoryAllocator;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
final class Properties {

  static final int DEFAULT_POOL_SIZE =
      pcap.common.util.Properties.getInt("pcap.codec.memory.pool.size", 10);

  static final int DEFAULT_MAX_POOL_SIZE =
      pcap.common.util.Properties.getInt("pcap.codec.memory.pool.max-size", 100);

  static final int DEFAULT_MEMORY_POOL_CAPACITY =
      pcap.common.util.Properties.getInt("pcap.codec.memory.pool.memory-capacity", 1500);

  static final MemoryAllocator DIRECT_ALLOCATOR;

  static {
    DIRECT_ALLOCATOR =
        MemoryAllocator.create(
            "NioPooledDirectMemoryAllocator",
            DEFAULT_POOL_SIZE,
            DEFAULT_MAX_POOL_SIZE,
            DEFAULT_MEMORY_POOL_CAPACITY);
  }

  private Properties() {}
}
