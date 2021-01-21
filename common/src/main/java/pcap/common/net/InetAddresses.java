/*
 * Copyright (c) 2020-2021 Pcap Project
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
 * @since 1.0.0
 */
public final class InetAddresses {

  private InetAddresses() {
    //
  }

  /**
   * From byte to {@link Inet4Address}.
   *
   * @param addr IPv4 address in byte array.
   * @return returns {@link Inet4Address} instance
   * @since 1.0.0
   */
  public static Inet4Address fromBytesToInet4Address(byte[] addr) {
    return (Inet4Address) bytesToInetAddress(addr);
  }

  /**
   * From byte to {@link Inet4Address} (little endian).
   *
   * @param addr IPv4 address in byte array.
   * @return returns {@link Inet4Address} instance
   * @since 1.0.0
   */
  public static Inet4Address fromBytesLEToInet4Address(byte[] addr) {
    return (Inet4Address) bytesToInetAddress(Arrays.reverse(addr));
  }

  /**
   * From int to {@link Inet4Address}.
   *
   * @param addr IPv4 address in integer.
   * @return returns {@link Inet4Address} instance
   * @since 1.0.0
   */
  public static Inet4Address fromIntegerToInet4Address(int addr) {
    return fromBytesToInet4Address(Bytes.toByteArray(addr));
  }

  /**
   * From int to {@link Inet4Address} (little endian).
   *
   * @param addr IPv4 address in integer.
   * @return returns {@link Inet4Address} instance
   * @since 1.0.0
   */
  public static Inet4Address fromIntegerLEToInet4Address(int addr) {
    return fromBytesToInet4Address(Bytes.toByteArrayLE(addr));
  }

  /**
   * From byte array to {@link Inet6Address}.
   *
   * @param addr IPv4 address in byte array.
   * @return returns {@link Inet6Address} instance.
   * @since 1.0.0
   */
  public static Inet6Address fromBytesToInet6Address(byte[] addr) {
    return (Inet6Address) bytesToInetAddress(addr);
  }

  /**
   * From byte array to {@link Inet6Address} (little endian).
   *
   * @param addr IPv4 address in byte array.
   * @return returns {@link Inet6Address} instance.
   * @since 1.0.0
   */
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
