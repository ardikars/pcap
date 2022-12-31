/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.common.net;

import java.util.ArrayList;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

class MacAddressTest {

  private static final String STRING_MAC_ADDRESS = MacAddress.DUMMY.toString();
  private static final long LONG_MAC_ADDRESS = MacAddress.DUMMY.toLong();
  private static final byte[] BYTES_MAC_ADDRESS = MacAddress.DUMMY.address();

  @Test
  void fromStringTest() {
    MacAddress macAddress = MacAddress.valueOf(STRING_MAC_ADDRESS);
    Assertions.assertNotNull(macAddress);
    Assertions.assertEquals(STRING_MAC_ADDRESS, macAddress.toString());
    Assertions.assertEquals(LONG_MAC_ADDRESS, macAddress.toLong());
    MacAddress macAddress2 = MacAddress.valueOf(STRING_MAC_ADDRESS.replace(":", "-"));
    Assertions.assertNotNull(macAddress2);
    Assertions.assertEquals(STRING_MAC_ADDRESS, macAddress2.toString());
    Assertions.assertEquals(LONG_MAC_ADDRESS, macAddress2.toLong());

    Assertions.assertEquals(
        MacAddress.DUMMY.toString(), MacAddress.fromString(MacAddress.DUMMY.toString()).toString());
    Assertions.assertEquals(
        MacAddress.DUMMY.toString(),
        MacAddress.fromString(MacAddress.DUMMY.toString().replace(":", "-")).toString());
    Assertions.assertEquals(
        MacAddress.DUMMY.toString(),
        MacAddress.fromString(MacAddress.DUMMY.toString().replace(":", "")).toString());
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            MacAddress.fromString(null);
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            MacAddress.fromString("de:ad");
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            MacAddress.fromString("de:ad:be:ef:c0-fe");
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            MacAddress.fromString("de:ad:be:ef:c0:fi");
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            MacAddress.fromString("de:ad:be:ef:c0:ve");
          }
        });
  }

  @Test
  void fromBytesTest() {
    MacAddress macAddress = MacAddress.valueOf(BYTES_MAC_ADDRESS);
    Assertions.assertNotNull(macAddress);
    Assertions.assertEquals(STRING_MAC_ADDRESS, macAddress.toString());
    Assertions.assertEquals(LONG_MAC_ADDRESS, macAddress.toLong());
  }

  @Test
  void fromLongTest() {
    MacAddress macAddress = MacAddress.valueOf(LONG_MAC_ADDRESS);
    Assertions.assertNotNull(macAddress);
    Assertions.assertEquals(STRING_MAC_ADDRESS, macAddress.toString());
    Assertions.assertEquals(LONG_MAC_ADDRESS, macAddress.toLong());
  }

  @Test
  void invalidMacAddressTest() {
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
  void buildTest() {
    MacAddress macAddress = MacAddress.DUMMY;
    Assertions.assertNotNull(macAddress);
    Assertions.assertEquals(MacAddress.MAC_ADDRESS_LENGTH, macAddress.length());
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
  void buildNegativeTest() {
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
  void validAddressNegativeTest() {
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
  void equalsAndHashCodeTest() {
    MacAddress macAddress = MacAddress.ZERO;
    MacAddress macAddressCmp = MacAddress.DUMMY;
    Object nullRef = null;
    Assertions.assertEquals(MacAddress.DUMMY, macAddressCmp);
    Assertions.assertNotEquals(macAddress, macAddressCmp);
    Assertions.assertNotEquals(macAddress.hashCode(), macAddressCmp.hashCode());
    Assertions.assertNotEquals(macAddress, new ArrayList<>(0));
    Assertions.assertNotEquals(macAddress, nullRef);
  }

  @Test
  void isValidStringTest() {
    Assertions.assertTrue(MacAddress.isValidString(MacAddress.DUMMY.toString()));
    Assertions.assertTrue(MacAddress.isValidString(MacAddress.DUMMY.toString().replace(":", "-")));
    Assertions.assertTrue(MacAddress.isValidString(MacAddress.DUMMY.toString().replace(":", "")));
    Assertions.assertFalse(MacAddress.isValidString(null));
    Assertions.assertFalse(MacAddress.isValidString("de:ad"));
    Assertions.assertFalse(MacAddress.isValidString("de:ad:be:ef:c0-fe"));
    Assertions.assertFalse(MacAddress.isValidString("de:ad:be:ef:c0:fi"));
    Assertions.assertFalse(MacAddress.isValidString("de:ad:be:ef:c0:ve"));
  }
}
