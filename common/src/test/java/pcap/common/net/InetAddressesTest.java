/*
 * Copyright (c) 2020-2022 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.common.net;

import java.net.Inet4Address;
import java.net.Inet6Address;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

class InetAddressesTest {

  @Test
  void fromBytesToInet4Address() {
    Inet4Address inet4Address = InetAddresses.fromBytesToInet4Address(new byte[] {127, 0, 0, 1});
    Assertions.assertEquals("127.0.0.1", inet4Address.getHostAddress());
  }

  @Test
  void fromBytesLEToInet4Address() {
    Inet4Address inet4Address = InetAddresses.fromBytesLEToInet4Address(new byte[] {127, 0, 0, 1});
    Assertions.assertEquals("1.0.0.127", inet4Address.getHostAddress());
  }

  @Test
  void fromIntegerToInet4Address() {
    Inet4Address inet4Address = InetAddresses.fromIntegerToInet4Address(0x7F000001);
    Assertions.assertEquals("127.0.0.1", inet4Address.getHostAddress());
  }

  @Test
  void fromIntegerLEToInet4Address() {
    Inet4Address inet4Address = InetAddresses.fromIntegerLEToInet4Address(0x7F000001);
    Assertions.assertEquals("1.0.0.127", inet4Address.getHostAddress());
  }

  @Test
  void fromBytesToInet6Address() {
    byte[] localhost = new byte[] {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    Inet6Address inet6Address = InetAddresses.fromBytesToInet6Address(localhost);
    Assertions.assertEquals("0:0:0:0:0:0:0:1", inet6Address.getHostAddress());
  }

  @Test
  void fromBytesLEToInet6Address() {
    byte[] localhost = new byte[] {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    Inet6Address inet6Address = InetAddresses.fromBytesLEToInet6Address(localhost);
    Assertions.assertEquals("100:0:0:0:0:0:0:0", inet6Address.getHostAddress());
  }

  @Test
  void bytesToInetAddress() {
    Assertions.assertNotNull(InetAddresses.bytesToInetAddress(new byte[] {127, 0, 0, 1}));
    Assertions.assertThrows(
        AssertionError.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            InetAddresses.bytesToInetAddress(null);
          }
        });
  }
}
