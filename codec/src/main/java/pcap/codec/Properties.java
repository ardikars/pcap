/** This code is licenced under the GPL version 2. */
package pcap.codec;

import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memories;
import pcap.common.memory.MemoryAllocator;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
final class Properties {

  static final MemoryAllocator BYTE_BUF_ALLOCATOR;

  private Properties() {}

  static {
    BYTE_BUF_ALLOCATOR = Memories.allocator();
  }
}
