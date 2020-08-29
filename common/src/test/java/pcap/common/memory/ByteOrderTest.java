package pcap.common.memory;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
public class ByteOrderTest {

  @Test
  public void nativeByteOrderTest() {
    Assertions.assertTrue(
        Memory.ByteOrder.NATIVE == Memory.ByteOrder.BIG_ENDIAN
            || Memory.ByteOrder.NATIVE == Memory.ByteOrder.LITTLE_ENDIAN);
  }

  @Test
  public void defaultByteOrderTest() {
    Memory memory = MemoryAllocator.create("NioDirectMemoryAllocator").allocate(4);
    Assertions.assertEquals(Memory.ByteOrder.BIG_ENDIAN, memory.byteOrder());
    memory.release();
  }

  @Test
  public void changeByteOrderTest() {
    Memory memory = MemoryAllocator.create("NioDirectMemoryAllocator").allocate(4);
    Assertions.assertEquals(Memory.ByteOrder.BIG_ENDIAN, memory.byteOrder());
    memory.byteOrder(Memory.ByteOrder.LITTLE_ENDIAN);
    Assertions.assertEquals(Memory.ByteOrder.LITTLE_ENDIAN, memory.byteOrder());
    memory.release();
  }
}
