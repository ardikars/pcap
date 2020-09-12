package pcap.common.net;

import java.net.UnknownHostException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
public class Inet6AddressTest {

  @Test
  public void valueOfStringTest() throws UnknownHostException {
    Assertions.assertNotNull(Inet6Address.valueOf("929e:c5c9:8487:978d:4fb3:fd72:dbef:c4e4"));
    Assertions.assertNotNull(Inet6Address.valueOf("929e:c5c9:8487:978d:4fb3::"));
    Assertions.assertNotNull(Inet6Address.valueOf("64:ff9b::192.0.2.128"));
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Inet6Address.valueOf("afjksdflssfdsfsdf");
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Inet6Address.valueOf("1");
          }
        });
  }

  @Test
  public void isMulticastAddressTest() {
    Assertions.assertTrue(Inet6Address.valueOf("FF01:0:0:0:0:0:0:BAC0").isMulticastAddress());
    Assertions.assertFalse(
        Inet6Address.valueOf("929e:c5c9:8487:978d:4fb3:fd72:dbef:c4e4").isMulticastAddress());
  }

  @Test
  public void isAnyLocalAddressTest() {
    Assertions.assertTrue(Inet6Address.ZERO.isAnyLocalAddress());
    Assertions.assertFalse(
        Inet6Address.valueOf("929e:c5c9:8487:978d:4fb3:fd72:dbef:c4e4").isAnyLocalAddress());
  }

  @Test
  public void isLoopbackAddressTest() {
    Assertions.assertTrue(Inet6Address.LOCALHOST.isLoopbackAddress());
    Assertions.assertFalse(Inet6Address.valueOf("::2").isLoopbackAddress());
    Assertions.assertFalse(Inet6Address.valueOf("2::1").isLoopbackAddress());
  }

  @Test
  public void isLinkLocalAddressTest() {
    Assertions.assertTrue(Inet6Address.valueOf("fe80::8243:201d:ba0c:7c03").isLinkLocalAddress());
    Assertions.assertFalse(Inet6Address.valueOf("fe70::8243:201d:ba0c:7c03").isLinkLocalAddress());
    Assertions.assertFalse(Inet6Address.valueOf("fa80::8243:201d:ba0c:7c03").isLinkLocalAddress());
  }

  @Test
  public void isSiteLocalAddressTest() {
    Assertions.assertTrue(Inet6Address.valueOf("fec0::8243:201d:ba0c:7c03").isSiteLocalAddress());
    Assertions.assertFalse(Inet6Address.valueOf("feb0::8243:201d:ba0c:7c03").isSiteLocalAddress());
    Assertions.assertFalse(Inet6Address.valueOf("fac0::8243:201d:ba0c:7c03").isSiteLocalAddress());
  }

  @Test
  public void isMcGlobalTest() {
    Assertions.assertTrue(Inet6Address.valueOf("ff0e::8243:201d:ba0c:7c03").isMcGlobal());
    Assertions.assertFalse(Inet6Address.valueOf("ff0b::8243:201d:ba0c:7c03").isMcGlobal());
    Assertions.assertFalse(Inet6Address.valueOf("fe0e::8243:201d:ba0c:7c03").isMcGlobal());
  }

  @Test
  public void isMcNodeLocalTest() {
    Assertions.assertTrue(Inet6Address.valueOf("ff01::8243:201d:ba0c:7c03").isMcNodeLocal());
    Assertions.assertFalse(Inet6Address.valueOf("ff02::8243:201d:ba0c:7c03").isMcNodeLocal());
    Assertions.assertFalse(Inet6Address.valueOf("fa01::8243:201d:ba0c:7c03").isMcNodeLocal());
  }

  @Test
  public void isMcLinkLocalTest() {
    Assertions.assertTrue(Inet6Address.valueOf("ff02::8243:201d:ba0c:7c03").isMcLinkLocal());
    Assertions.assertFalse(Inet6Address.valueOf("ff01::8243:201d:ba0c:7c03").isMcLinkLocal());
    Assertions.assertFalse(Inet6Address.valueOf("fa02::8243:201d:ba0c:7c03").isMcLinkLocal());
  }

  @Test
  public void isMcSiteLocalTest() {
    Assertions.assertTrue(Inet6Address.valueOf("ff05::8243:201d:ba0c:7c03").isMcSiteLocal());
    Assertions.assertFalse(Inet6Address.valueOf("ff01::8243:201d:ba0c:7c03").isMcSiteLocal());
    Assertions.assertFalse(Inet6Address.valueOf("fa05::8243:201d:ba0c:7c03").isMcSiteLocal());
  }

  @Test
  public void isMcOrgLocalTest() {
    Assertions.assertTrue(Inet6Address.valueOf("ff08::8243:201d:ba0c:7c03").isMcOrgLocal());
    Assertions.assertFalse(Inet6Address.valueOf("ff04::8243:201d:ba0c:7c03").isMcOrgLocal());
    Assertions.assertFalse(Inet6Address.valueOf("fa08::8243:201d:ba0c:7c03").isMcOrgLocal());
  }

  @Test
  public void toLongTest() {
    Inet6Address.LOCALHOST.toLong();
  }

  @Test
  public void equalsAndHashCodeTest() {
    Assertions.assertEquals(Inet6Address.LOCALHOST, Inet6Address.valueOf("::1"));
    Assertions.assertEquals(
        Inet6Address.LOCALHOST.hashCode(), Inet6Address.valueOf("::1").hashCode());
    Assertions.assertArrayEquals(
        Inet6Address.valueOf("ff08::8243:201d:ba0c:7c03").address(),
        Inet6Address.valueOf("ff08::8243:201d:ba0c:7c03").address());
    Assertions.assertNotEquals(
        Inet6Address.valueOf("ff08::8243:201d:ba0c:7c03"), Inet6Address.valueOf("::1"));
    Assertions.assertNotEquals(
        Inet6Address.valueOf("ff08::8243:201d:ba0c:7c03").hashCode(),
        Inet6Address.valueOf("::1").hashCode());
    Assertions.assertFalse(Inet6Address.LOCALHOST.equals(null));
    Assertions.assertFalse(Inet6Address.LOCALHOST.equals(""));
    Assertions.assertTrue(Inet6Address.LOCALHOST.equals(Inet6Address.LOCALHOST));
  }

  @Test
  public void toStringTest() {
    Assertions.assertNotNull(Inet6Address.LOCALHOST.toString());
    Assertions.assertNotNull(Inet6Address.valueOf("ff08::8243:201d:ba0c:7c03").toString());
    Assertions.assertNotNull(Inet6Address.valueOf("0000::0000:0000:0000:0001").toString());
  }
}
