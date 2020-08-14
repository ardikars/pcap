package pcap.api;

import java.nio.ByteBuffer;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.common.memory.Memory;
import pcap.common.memory.MemoryAllocator;
import pcap.spi.PacketBuffer;

@RunWith(JUnitPlatform.class)
public class PacketBufferUtilsTest {

  @Test
  public void fromDirectByteBufferTest() {
    ByteBuffer buffer = ByteBuffer.allocateDirect(8);
    PacketBuffer packetBuffer = PacketBufferUtils.fromDirectByteBuffer(buffer);
    Assertions.assertNotNull(packetBuffer);
  }

  @Test
  public void fromDirectByteBufferNegativeTest() {
    ByteBuffer buffer = ByteBuffer.allocate(8);
    Assertions.assertThrows(
        IllegalArgumentException.class, () -> PacketBufferUtils.fromDirectByteBuffer(buffer));
  }

  @Test
  public void fromMemoryTest() {
    ByteBuffer buffer = ByteBuffer.allocateDirect(8);
    Memory memory = MemoryAllocator.create("NioDirectMemoryAllocator").wrap(buffer);
    PacketBuffer packetBuffer = PacketBufferUtils.fromMemory(memory);
    Assertions.assertNotNull(packetBuffer);
    memory.release();
  }

  @Test
  public void fromMemoryNegativeTest() {
    ByteBuffer buffer = ByteBuffer.allocate(8);
    Memory memory = MemoryAllocator.create("NioHeapMemoryAllocator").wrap(buffer);
    Assertions.assertThrows(
        IllegalArgumentException.class, () -> PacketBufferUtils.fromMemory(memory));
  }
}
