package pcap.common.net;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
public class Inet4AddressTest {

  @Test
  public void valueOfStringTest() {
    String valid = "10.14.204.25";
    String inValidLength = "10.14.204";
    String inValidNumber = "10.14.204.03";
    String inValidTooLargeNumber = "10.14.204.257";
    Assertions.assertNotNull(Inet4Address.valueOf(valid));
    Assertions.assertThrows(IllegalArgumentException.class, () -> Inet4Address.valueOf(""));
    Assertions.assertThrows(IllegalArgumentException.class, () -> Inet4Address.valueOf("19216811"));
    Assertions.assertThrows(
        IllegalArgumentException.class, () -> Inet4Address.valueOf(inValidLength));
    Assertions.assertThrows(
        IllegalArgumentException.class, () -> Inet4Address.valueOf(inValidNumber));
    Assertions.assertThrows(
        IllegalArgumentException.class, () -> Inet4Address.valueOf(inValidTooLargeNumber));
  }

  @Test
  public void valueOfByteTest() {
    Assertions.assertEquals(
        Inet4Address.LOCALHOST, Inet4Address.valueOf(new byte[] {127, 0, 0, 1}));
    Assertions.assertEquals(Inet4Address.ZERO, Inet4Address.valueOf(new byte[] {0, 0, 0, 0}));
    Assertions.assertThrows(
        IllegalArgumentException.class, () -> Inet4Address.valueOf(new byte[] {127, 0, 1}));
  }

  @Test
  public void valueOfIntTest() {
    int mask = 0xFFFFFF00; // 255.255.255.0 or 4294967040
    int value = Inet4Address.valueOf("255.255.255.0").toInt();
    Assertions.assertEquals(mask, value);
    Assertions.assertEquals(Inet4Address.valueOf(value), Inet4Address.valueOf("255.255.255.0"));
  }

  @Test
  public void checkAddressTest() {
    Assertions.assertTrue(Inet4Address.valueOf("224.0.0.0").isMulticastAddress());
    Assertions.assertFalse(Inet4Address.valueOf("10.0.0.0").isMulticastAddress());
    Assertions.assertTrue(Inet4Address.valueOf("0.0.0.0").isAnyLocalAddress());
    Assertions.assertFalse(Inet4Address.valueOf("192.168.0.0").isAnyLocalAddress());
    Assertions.assertTrue(Inet4Address.LOCALHOST.isLoopbackAddress());
    Assertions.assertFalse(Inet4Address.valueOf("192.168.0.0").isLoopbackAddress());
    Assertions.assertTrue(Inet4Address.valueOf("169.254.0.0").isLinkLocalAddress());
    Assertions.assertFalse(Inet4Address.valueOf("169.255.0.0").isLinkLocalAddress());
    Assertions.assertFalse(Inet4Address.valueOf("192.254.0.0").isLinkLocalAddress());

    Assertions.assertTrue(Inet4Address.valueOf("10.0.0.0").isSiteLocalAddress());
    Assertions.assertFalse(Inet4Address.valueOf("103.0.0.0").isSiteLocalAddress());
    Assertions.assertTrue(Inet4Address.valueOf("172.16.0.0").isSiteLocalAddress());
    Assertions.assertFalse(Inet4Address.valueOf("172.168.0.0").isSiteLocalAddress());
    Assertions.assertFalse(Inet4Address.valueOf("192.16.0.0").isSiteLocalAddress());
    Assertions.assertTrue(Inet4Address.valueOf("192.168.0.0").isSiteLocalAddress());
    Assertions.assertFalse(Inet4Address.valueOf("192.0.0.0").isSiteLocalAddress());
    Assertions.assertFalse(Inet4Address.valueOf("0.168.0.0").isSiteLocalAddress());

    Assertions.assertTrue(Inet4Address.valueOf("225.0.0.0").isMcGlobal());
    Assertions.assertFalse(Inet4Address.valueOf("224.0.0.0").isMcGlobal());
    Assertions.assertTrue(Inet4Address.valueOf("224.0.1.0").isMcGlobal());
    Assertions.assertTrue(Inet4Address.valueOf("224.1.0.0").isMcGlobal());
    Assertions.assertTrue(Inet4Address.valueOf("224.1.0.0").isMcGlobal());
    Assertions.assertTrue(Inet4Address.valueOf("224.0.1.0").isMcGlobal());
    Assertions.assertFalse(Inet4Address.valueOf("223.1.0.0").isMcGlobal());
    Assertions.assertFalse(Inet4Address.valueOf("224.0.0.0").isMcGlobal());
    Assertions.assertFalse(Inet4Address.valueOf("240.238.1.1").isMcGlobal());
    Assertions.assertFalse(Inet4Address.valueOf("223.1.1.1").isMcGlobal());
    Assertions.assertFalse(Inet4Address.valueOf("239.1.1.1").isMcGlobal());

    Assertions.assertFalse(Inet4Address.LOCALHOST.isMcNodeLocal());

    Assertions.assertTrue(Inet4Address.valueOf("224.0.0.0").isMcLinkLocal());
    Assertions.assertFalse(Inet4Address.valueOf("10.0.0.0").isMcLinkLocal());
    Assertions.assertFalse(Inet4Address.valueOf("224.1.0.0").isMcLinkLocal());
    Assertions.assertFalse(Inet4Address.valueOf("224.0.1.0").isMcLinkLocal());

    Assertions.assertTrue(Inet4Address.valueOf("239.255.0.0").isMcSiteLocal());
    Assertions.assertFalse(Inet4Address.valueOf("239.1.0.0").isMcSiteLocal());
    Assertions.assertFalse(Inet4Address.valueOf("1.255.0.0").isMcSiteLocal());

    Assertions.assertTrue(Inet4Address.valueOf("239.192.0.0").isMcOrgLocal());
    Assertions.assertFalse(Inet4Address.valueOf("10.192.0.0").isMcOrgLocal());
    Assertions.assertFalse(Inet4Address.valueOf("239.191.0.0").isMcOrgLocal());
    Assertions.assertFalse(Inet4Address.valueOf("239.196.0.0").isMcOrgLocal());
  }

  @Test
  public void equalAndHasCodeTest() {
    Inet4Address address = Inet4Address.LOCALHOST;
    Assertions.assertFalse(address.equals(null));
    Assertions.assertFalse(address.equals(""));
    Assertions.assertTrue(address.equals(Inet4Address.LOCALHOST));
    Assertions.assertTrue(address.equals(Inet4Address.valueOf("127.0.0.1")));
  }
}
