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

  @Test
  public void invalidMacAddressTest() {
    Assertions.assertThrows(IllegalArgumentException.class, () -> MacAddress.valueOf(new byte[0]));
    Assertions.assertThrows(IllegalArgumentException.class, () -> MacAddress.valueOf(-1));
    Assertions.assertThrows(IllegalArgumentException.class, () -> MacAddress.valueOf(""));
    Assertions.assertThrows(IllegalArgumentException.class, () -> MacAddress.valueOf("23423d.."));
    Assertions.assertFalse(MacAddress.isValidAddress("##%DF234"));
  }

  @Test
  public void buildTest() {
    MacAddress macAddress = MacAddress.DUMMY;
    Assertions.assertNotNull(macAddress);
    Assertions.assertEquals(macAddress.length(), MacAddress.MAC_ADDRESS_LENGTH);
    Assertions.assertEquals(0L, MacAddress.ZERO.toLong());
    Assertions.assertEquals(true, MacAddress.BROADCAST.isBroadcast());
    Assertions.assertEquals(true, MacAddress.IPV4_MULTICAST.isMulticast());
    Assertions.assertEquals(true, MacAddress.IPV4_MULTICAST_MASK.isMulticast());
    Assertions.assertEquals(true, MacAddress.IPV4_MULTICAST_MASK.isMulticast());
    Assertions.assertEquals(true, MacAddress.ZERO.isGloballyUnique());
    Assertions.assertEquals(true, MacAddress.valueOf("00:01:01:01:01:01").isUnicast());
    Assertions.assertEquals(true, MacAddress.valueOf("00:01:01:01:01:01").isUnicast());
  }
}
