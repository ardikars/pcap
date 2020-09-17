package pcap.api.jdk7;

import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
public class DefaultPacketBuffferTest {

  @Test
  public void newInstance() {
    int size = 8;
    DefaultPacketBuffer packetBuffer = new DefaultPacketBuffer();
    Assertions.assertNull(packetBuffer.buf);
    packetBuffer.buf = new Memory(size);
    packetBuffer.write();

    Pointer pointer = packetBuffer.getPointer();
    DefaultPacketBuffer fromPointer = new DefaultPacketBuffer(pointer, size);
    Assertions.assertNotNull(fromPointer.buf);

    DefaultPacketBuffer withSize = new DefaultPacketBuffer(size);
    Assertions.assertNotNull(withSize.buf);
    Assertions.assertEquals(0, withSize.readerIndex());
    Assertions.assertEquals(size, withSize.writerIndex());
    Assertions.assertEquals(size, withSize.capacity());
    Assertions.assertEquals(0, withSize.address());

    withSize.readerIndex(withSize.capacity());
    Assertions.assertEquals(withSize.capacity(), withSize.readerIndex());

    withSize.writerIndex(withSize.capacity());
    Assertions.assertEquals(withSize.capacity(), withSize.writerIndex());

    Assertions.assertFalse(withSize.release());
  }
}
