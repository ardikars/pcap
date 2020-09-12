/** This code is licenced under the GPL version 2. */
package pcap.common.net;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
public class MacAddressTest {

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
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            MacAddress.valueOf(new byte[0]);
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            MacAddress.valueOf(-1);
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            MacAddress.valueOf("");
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            MacAddress.valueOf("23423d..");
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            MacAddress.valueOf("de:ad:be:ef:c0");
          }
        });
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
    Assertions.assertEquals(false, MacAddress.ZERO.isMulticast());
    Assertions.assertEquals(false, MacAddress.BROADCAST.isMulticast());
    Assertions.assertEquals(true, MacAddress.ZERO.isGloballyUnique());
    Assertions.assertEquals(false, MacAddress.BROADCAST.isGloballyUnique());
    Assertions.assertEquals(true, MacAddress.valueOf("00:01:01:01:01:01").isUnicast());
    Assertions.assertEquals(false, MacAddress.valueOf("03:01:01:01:01:01").isUnicast());
  }

  @Test
  public void buildNegativeTest() {
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            MacAddress.valueOf("zzz");
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            MacAddress.valueOf("00:01:01:01:01:01:01");
          }
        });
  }

  @Test
  public void validAddressNegativeTest() {
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            MacAddress.isValidAddress("");
          }
        });
  }

  @Test
  public void ouiTest() {
    Assertions.assertEquals(
        new MacAddress.Oui(1, "UNKNOWN"), MacAddress.valueOf("E8-6F-38-39-3D-BF").oui());
    Assertions.assertEquals(
        MacAddress.Oui.CISCO_00000C, MacAddress.valueOf("00-00-0C-39-3D-BF").oui());
    MacAddress.Oui oui = new MacAddress.Oui(0x08005B, "Random");
    MacAddress.Oui.register(oui);
    Assertions.assertNotNull(oui);
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            new MacAddress.Oui(16777216, "Random");
          }
        });
  }

  @Test
  public void equalsAndHashCodeTest() {
    MacAddress macAddress = MacAddress.ZERO;
    MacAddress macAddressCmp = MacAddress.DUMMY;
    Assertions.assertTrue(macAddress.equals(MacAddress.ZERO));
    Assertions.assertFalse(macAddress.equals(macAddressCmp));
    Assertions.assertFalse(macAddress.hashCode() == macAddressCmp.hashCode());
    Assertions.assertFalse(macAddress.equals(""));
    Assertions.assertFalse(macAddress.equals(null));
  }

  @Test
  public void ouiCompareTest() {
    MacAddress.Oui cisco = MacAddress.Oui.CISCO_00000C;
    MacAddress.Oui ibm = MacAddress.Oui.IBM_08005A;
    Assertions.assertTrue(cisco.compareTo(ibm) < 0);
    Assertions.assertTrue(ibm.compareTo(cisco) > 0);
    Assertions.assertTrue(ibm.compareTo(ibm) == 0);
  }
}
