package pcap.common.net;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
public class RawAddressTest {

  @Test
  public void newInstanceTest() {
    RawAddress rawAddress = RawAddress.valueOf(new byte[] {0, 1, 2, 3});
    Assertions.assertNotNull(rawAddress.address());
  }
}
