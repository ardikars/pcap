/** This code is licenced under the GPL version 2. */
package pcap.common.net;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
public class MacAddressTest extends BaseTest {

  private static final String STRING_MAC_ADDRESS = MacAddress.DUMMY.toString();
  private static final long LONG_MAC_ADDRESS = MacAddress.DUMMY.toLong();
  private static final byte[] BYTES_MAC_ADDRESS = MacAddress.DUMMY.address();

  @Test
  public void fromStringTest() {
    MacAddress macAddress = MacAddress.valueOf(STRING_MAC_ADDRESS);
    Assertions.assertNotNull(macAddress);
    Assertions.assertEquals(STRING_MAC_ADDRESS, macAddress.toString());
    Assertions.assertEquals(LONG_MAC_ADDRESS, macAddress.toLong());
  }

  @Test
  public void fromBytesTest() {
    MacAddress macAddress = MacAddress.valueOf(BYTES_MAC_ADDRESS);
    Assertions.assertNotNull(macAddress);
    Assertions.assertEquals(STRING_MAC_ADDRESS, macAddress.toString());
    Assertions.assertEquals(LONG_MAC_ADDRESS, macAddress.toLong());
  }

  @Test
  public void fromLongTest() {
    MacAddress macAddress = MacAddress.valueOf(LONG_MAC_ADDRESS);
    Assertions.assertNotNull(macAddress);
    Assertions.assertEquals(STRING_MAC_ADDRESS, macAddress.toString());
    Assertions.assertEquals(LONG_MAC_ADDRESS, macAddress.toLong());
  }
}
