/** This code is licenced under the GPL version 2. */
package pcap.codec.arp;

import org.junit.jupiter.api.AfterEach;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.codec.BaseTest;
import pcap.codec.ethernet.Ethernet;
import pcap.common.memory.Memory;
import pcap.common.util.Hexs;

@RunWith(JUnitPlatform.class)
public class ArpTest extends BaseTest {

  private byte[] data = Hexs.parseHex(ETHERNET_II_ARP);

  private Memory buf = allocator.allocate(data.length);

  @Override
  public void before() {
    buf.writeBytes(data);
    ethernet = Ethernet.newPacket(buf);
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
