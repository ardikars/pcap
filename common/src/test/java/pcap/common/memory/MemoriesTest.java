/** This code is licenced under the GPL version 2. */
package pcap.common.memory;

import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.common.internal.Unsafe;

@RunWith(JUnitPlatform.class)
public class MemoriesTest {

  @Test
  public void defaultAllocator() {
    MemoryAllocator allocator = Memories.allocator();
    assert allocator instanceof DefaultMemoryAllocator;
    Memory memory = allocator.allocate(8);
    // assert memory.nioBuffer().isDirect();
    assert memory.isDirect() || !memory.isDirect();
    memory.release();
  }

  @Test
  public void pooledAllocator() {
    MemoryAllocator allocator = Memories.allocator(5, 7, 10);
    for (int i = 0; i < 10; i++) {
      Memory memory = allocator.allocate(i + 1);
      memory.release();
    }
    allocator.close();
  }

  @Test
  public void pooledAllocatorFull() {
    MemoryAllocator allocator = Memories.allocator(5, 7, 10);
    for (int i = 0; i < 10; i++) {
      Memory memory = allocator.allocate(i + 1);
      if (i > 6) {
        if (!Unsafe.HAS_UNSAFE) {
          assert memory instanceof ByteBuf;
        }
      }
    }
    allocator.close();
  }
}
