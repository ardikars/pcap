/** This code is licenced under the GPL version 2. */
package pcap.spi;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
public class PcapDirectionTest {

  @Test
  public void directionTest() {
    Assertions.assertEquals(Pcap.Direction.PCAP_D_INOUT, Pcap.Direction.fromString("PCAP_D_INOUT"));
    Assertions.assertEquals(Pcap.Direction.PCAP_D_IN, Pcap.Direction.fromString("PCAP_D_IN"));
    Assertions.assertEquals(Pcap.Direction.PCAP_D_OUT, Pcap.Direction.fromString("PCAP_D_OUT"));
    Assertions.assertEquals(Pcap.Direction.PCAP_D_INOUT, Pcap.Direction.fromString(""));
  }
}
