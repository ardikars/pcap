/*
 * Copyright (c) 2020 Pcap <contact@pcap.ardikars.com>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.common.net;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import pcap.common.util.Arrays;
import pcap.common.util.Bytes;

/**
 * InetAddress utils.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
public class InetAddresses {

  private InetAddresses() {
    //
  }

  public static Inet4Address fromBytesToInet4Address(byte[] addr) {
    return (Inet4Address) bytesToInetAddress(addr);
  }

  public static Inet4Address fromBytesLEToInet4Address(byte[] addr) {
    return (Inet4Address) bytesToInetAddress(Arrays.reverse(addr));
  }

  public static Inet4Address fromIntegerToInet4Address(int addr) {
    return fromBytesToInet4Address(Bytes.toByteArray(addr));
  }

  public static Inet4Address fromIntegerLEToInet4Address(int addr) {
    return fromBytesToInet4Address(Bytes.toByteArrayLE(addr));
  }

  public static Inet6Address fromBytesToInet6Address(byte[] addr) {
    return (Inet6Address) bytesToInetAddress(addr);
  }

  public static Inet6Address fromBytesLEToInet6Address(byte[] addr) {
    return (Inet6Address) bytesToInetAddress(Arrays.reverse(addr));
  }

  static InetAddress bytesToInetAddress(byte[] addr) {
    try {
      return InetAddress.getByAddress(addr);
    } catch (UnknownHostException e) {
      throw new AssertionError(e);
    }
  }
}
