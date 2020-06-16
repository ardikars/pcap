/** This code is licenced under the GPL version 2. */
package pcap.codec.ip;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.codec.BaseTest;
import pcap.codec.ethernet.Ethernet;
import pcap.codec.ip.ip6.Authentication;
import pcap.common.memory.Memory;
import pcap.common.util.Hexs;

/** @author <a href="mailto:contact@ardikars.com">Langkuy</a> */
@RunWith(JUnitPlatform.class)
public class Ip6AuthenticationTest extends BaseTest {

  private final byte[] data = Hexs.parseHex(IPV6_AUTHENTICATION);

  private final Memory buf = allocator.allocate(data.length);

  @Override
  public void before() {
    buf.writeBytes(data);
    ethernet = Ethernet.newPacket(buf);
    final Authentication first = ethernet.getFirst(Authentication.class);
    Memory memory = first.buffer();
    Assertions.assertEquals(0, memory.readerIndex());
    Assertions.assertEquals(first.header().length(), memory.writerIndex());
  }

  @Test
  public void buildTest() {

  }

  @AfterEach
  public void after() {
    try {
      buf.release();
    } catch (Throwable e) {
      //
    }
  }
}
