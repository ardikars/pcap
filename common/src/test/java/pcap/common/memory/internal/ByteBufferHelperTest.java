/** This code is licenced under the GPL version 2. */
package pcap.common.memory.interlan;

import java.nio.ByteBuffer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.common.internal.ByteBufferHelper;
import pcap.common.internal.UnsafeHelper;
import pcap.common.memory.accessor.MemoryAccessor;
import pcap.common.memory.accessor.MemoryAccessors;

@RunWith(JUnitPlatform.class)
public class ByteBufferHelperTest {

  private boolean hasUnsafe = UnsafeHelper.isUnsafeAvailable();
  private MemoryAccessor accessor = hasUnsafe ? MemoryAccessors.memoryAccessor() : null;

  private ByteBuffer buffer;

  @BeforeEach
  public void before() {
    buffer = ByteBuffer.allocateDirect(8);
  }

  @Test
  public void directByteBufferAddressTest() {
    if (hasUnsafe) {
      assert ByteBufferHelper.directByteBufferAddress(buffer) != 0;
    }
  }

  @Test
  @Disabled
  public void wrapDirectByteBufferTest() {
    if (hasUnsafe) {
      int size = 8;
      long address = accessor.allocate(size);
      ByteBuffer buffer = ByteBufferHelper.wrapDirectByteBuffer(address, size);
      assert buffer != null;
      assert buffer.capacity() == size;
      release(buffer);
    }
  }

  @AfterEach
  public void after() {
    release(buffer);
  }

  private void release(ByteBuffer buffer) {
    if (hasUnsafe) {
      long address = ByteBufferHelper.directByteBufferAddress(buffer);
      accessor.deallocate(address);
    }
  }
}
