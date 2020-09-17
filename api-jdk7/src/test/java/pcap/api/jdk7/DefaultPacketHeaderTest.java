package pcap.api.jdk7;

import com.sun.jna.NativeLong;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
public class DefaultPacketHeaderTest {

  @Test
  public void newInstance() {
    DefaultPacketHeader packetHeader = new DefaultPacketHeader();
    packetHeader.ts = new DefaultTimestamp();
    packetHeader.ts.tv_sec = new NativeLong(1);
    packetHeader.ts.tv_usec = new NativeLong(1);
    packetHeader.len = 1;
    packetHeader.caplen = 1;
    packetHeader.write();
    Assertions.assertEquals(1, packetHeader.timestamp().second());
    Assertions.assertEquals(1, packetHeader.timestamp().microSecond());
    Assertions.assertEquals(1, packetHeader.captureLength());
    Assertions.assertEquals(1, packetHeader.length());

    DefaultPacketHeader fromPointer = new DefaultPacketHeader(packetHeader.getPointer());
    Assertions.assertEquals(1, fromPointer.timestamp().second());
    Assertions.assertEquals(1, fromPointer.timestamp().microSecond());
    Assertions.assertEquals(1, fromPointer.captureLength());
    Assertions.assertEquals(1, fromPointer.length());
  }
}
