/** This code is licenced under the GPL version 2. */
package pcap.codec.ethernet;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.codec.BaseTest;
import pcap.common.memory.Memory;
import pcap.common.net.MacAddress;
import pcap.common.util.Hexs;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@RunWith(JUnitPlatform.class)
public class VlanArpTest extends BaseTest {

  private byte[] data = Hexs.parseHex(ETHERNET_II_Q_IN_Q_ARP);

  private Memory buf = allocator.allocate(data.length);

  @Override
  public void before() {
    buf.writeBytes(data);
    ethernet = Ethernet.newPacket(buf);
  }

  @Test
  public void modify() {
    final Ethernet build =
        ethernet
            .header()
            .builder()
            .sourceMacAddress(MacAddress.valueOf("de:de:de:ad:dd:12"))
            .destinationMacAddress(MacAddress.valueOf("da:de:de:ad:dd:12"))
            .build();
    System.out.println(build);
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
