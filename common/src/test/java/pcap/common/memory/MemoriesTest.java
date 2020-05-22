/** This code is licenced under the GPL version 2. */
package pcap.common.memory;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.common.memory.internal.allocator.DirectMemoryAllocator;
import pcap.common.memory.internal.allocator.HeapMemoryAllocator;
import pcap.common.memory.internal.nio.PooledDirectByteBuffer;

@RunWith(JUnitPlatform.class)
public class MemoriesTest {

  @Test
  public void defaultAllocator() {
    MemoryAllocator allocator = Memories.allocator();
    Assertions.assertTrue(allocator instanceof HeapMemoryAllocator);
    Memory memory = allocator.allocate(8);
    memory.release();
  }

  public void directAllocator() {
    MemoryAllocator allocator = Memories.directAllocator();
    Assertions.assertTrue(allocator instanceof DirectMemoryAllocator);
    Memory memory = allocator.allocate(8);
    memory.release();
  }

  @Test
  public void pooledAllocator() {
    MemoryAllocator allocator = Memories.allocator(5, 10, 10);
    MemoryAllocator allocatorDirect = Memories.directAllocator(5, 10, 10);
    for (int i = 0; i < 10; i++) {
      PooledDirectByteBuffer heap = (PooledDirectByteBuffer) allocatorDirect.allocate(i + 1);
      PooledDirectByteBuffer direct = (PooledDirectByteBuffer) allocatorDirect.allocate(i + 1);
      direct.retain();
      direct.retain();
      direct.retain();
      direct.refCnt(1);
      direct.refCnt(1);
      direct.refCnt(1);
      direct.retain(3);
      direct.refCnt(3);
      direct.release();

      heap.retain();
      heap.retain();
      heap.retain();
      heap.refCnt(1);
      heap.refCnt(1);
      heap.refCnt(1);
      heap.retain(3);
      heap.refCnt(3);
      heap.release();
    }
    assert true;
  }

  @Test
  public void pooledAllocatorFull() {
    MemoryAllocator allocator = Memories.allocator(1, 2, 10);
    MemoryAllocator allocatorDirect = Memories.directAllocator(1, 2, 10);

    final Memory allocate = allocator.allocate(3);
    allocate.release();

    final Memory allocateDirect = allocatorDirect.allocate(3);
    allocateDirect.release();

    Assertions.assertThrows(IllegalArgumentException.class, () -> allocator.allocate(11));
    Assertions.assertThrows(IllegalArgumentException.class, () -> allocatorDirect.allocate(11));
    Assertions.assertThrows(IllegalArgumentException.class, () -> allocator.allocate(-1));
    Assertions.assertThrows(IllegalArgumentException.class, () -> allocatorDirect.allocate(-1));
    Assertions.assertThrows(IllegalArgumentException.class, () -> allocator.allocate(-1, -1));
    Assertions.assertThrows(IllegalArgumentException.class, () -> allocatorDirect.allocate(-1, -1));
    Assertions.assertThrows(IllegalArgumentException.class, () -> allocator.allocate(-1, -1, 0, 0));
    Assertions.assertThrows(
        IllegalArgumentException.class, () -> allocatorDirect.allocate(-1, -1, 0, 0));
  }
}
