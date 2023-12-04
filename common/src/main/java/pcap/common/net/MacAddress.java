/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.common.net;

import java.io.Serializable;
import java.util.Arrays;
import java.util.regex.Pattern;
import pcap.common.util.Hexs;
import pcap.common.util.Strings;
import pcap.common.util.Validate;

/**
 * Wrapper for raw mac address.
 *
 * @since 1.0.0
 */
public final class MacAddress implements Serializable {

  /** MAC Address Length. */
  public static final int MAC_ADDRESS_LENGTH = 6;

  private static final Pattern REGEX = Pattern.compile("[:-]");

  /** Zero MAC Address (00:00:00:00:00:00). */
  public static final MacAddress ZERO = valueOf("00:00:00:00:00:00");

  /** Dummy MAC Address (de:ad:be:ef:c0:fe). */
  public static final MacAddress DUMMY = valueOf("de:ad:be:ef:c0:fe");

  /** Broadcast MAC Address (ff:ff:ff:ff:ff:ff). */
  public static final MacAddress BROADCAST = valueOf("ff:ff:ff:ff:ff:ff");

  /** Multicast Address. */
  public static final MacAddress IPV4_MULTICAST = valueOf("01:00:5e:00:00:00");

  /** Multicast mask. */
  public static final MacAddress IPV4_MULTICAST_MASK = valueOf("ff:ff:ff:80:00:00");

  private final byte[] address;

  private MacAddress(byte[] address) {
    Validate.notIllegalArgument(
        address.length == MAC_ADDRESS_LENGTH,
        String.format("Address length: (%d) expected(%d)", address.length, MAC_ADDRESS_LENGTH));
    this.address = Arrays.copyOf(address, MacAddress.MAC_ADDRESS_LENGTH);
  }

  // internal API
  private static int separator0(String stringAddress) {
    if (stringAddress == null) {
      return -1;
    }
    final int length = stringAddress.length();
    if (length != 17 && length != 12) {
      return -1;
    }
    final int separator = length == 17 ? 3 : 2;
    if (separator == 3) { // with separator
      // check separator
      int n = 0;
      for (int i = 2; i <= 14; i += separator) {
        n += stringAddress.charAt(i);
      }
      if (n == 290 || n == 225) {
        return separator;
      } else {
        return -1;
      }
    }
    return separator;
  }

  /**
   * Determines the MacAddress address.
   *
   * @param stringAddress MAC string address.
   * @return an Mac address object.
   * @since 1.5.0
   */
  public static MacAddress fromString(String stringAddress) {
    final int separator = separator0(stringAddress);
    if (separator < 0) {
      throw new IllegalArgumentException("Invalid mac address: " + stringAddress);
    }
    final byte[] bytes = new byte[MAC_ADDRESS_LENGTH];
    assert stringAddress != null;
    final int length = stringAddress.length();
    int offset = 0;
    for (int i = 0; i < length; i += separator) {
      final int hi = Hexs.decodeHexNibble(stringAddress.charAt(i));
      final int lo = Hexs.decodeHexNibble(stringAddress.charAt(i + 1));
      if (hi == -1 || lo == -1) {
        throw new IllegalArgumentException(
            String.format(
                "Invalid hex address '%s' at index %d of '%s'",
                stringAddress.subSequence(i, i + 2), i, stringAddress));
      }
      bytes[offset] = (byte) ((hi << 4) + lo);
      offset += 1;
    }
    return valueOf(bytes);
  }

  /**
   * Determines the MacAddress address.
   *
   * @param stringAddress MAC string address.
   * @return an Mac address object.
   * @since 1.0.0
   */
  public static MacAddress valueOf(String stringAddress) {
    Validate.notIllegalArgument(
        !Strings.blank(stringAddress), "Address must be not empty or blank.");
    Validate.notIllegalArgument(
        isValidAddress(stringAddress), String.format("Invalid address: %s.", stringAddress));
    final String[] elements = REGEX.split(stringAddress);
    final byte[] b = new byte[MAC_ADDRESS_LENGTH];
    for (int i = 0; i < MAC_ADDRESS_LENGTH; i++) {
      final String element = elements[i];
      b[i] = (byte) Integer.parseInt(element, 16);
    }
    return valueOf(b);
  }

  /**
   * Determines the MacAddress address.
   *
   * @param bytesAddress MAC bytes address.
   * @return an Mac address object.
   * @since 1.0.0
   */
  public static MacAddress valueOf(final byte[] bytesAddress) {
    return fromBytes(bytesAddress);
  }

  /**
   * Determines the MacAddress address.
   *
   * @param bytes MAC bytes address.
   * @return an Mac address object.
   * @since 1.5.0
   */
  public static MacAddress fromBytes(final byte[] bytes) {
    return new MacAddress(bytes);
  }

  /**
   * Determines the MacAddress address.
   *
   * @param longAddress MAC long address.
   * @return an Mac address object.
   * @since 1.0.0
   */
  public static MacAddress valueOf(final long longAddress) {
    return fromLong(longAddress);
  }

  /**
   * Determines the MacAddress address.
   *
   * @param longAddress MAC long address.
   * @return an Mac address object.
   * @since 1.5.0
   */
  public static MacAddress fromLong(final long longAddress) {
    Validate.notIllegalArgument(
        longAddress >= 0, String.format("Address: %d expected(address > 0)", longAddress));
    final byte[] bytes =
        new byte[] {
          (byte) (longAddress >> 40 & 0xff),
          (byte) (longAddress >> 32 & 0xff),
          (byte) (longAddress >> 24 & 0xff),
          (byte) (longAddress >> 16 & 0xff),
          (byte) (longAddress >> 8 & 0xff),
          (byte) (longAddress & 0xff)
        };
    return valueOf(bytes);
  }

  /**
   * Validate given mac string address.
   *
   * @param stringAddress mac string address.
   * @return a {@code boolean} indicating if the stringAddress is a valid mac address; or false
   *     otherwise.
   * @since 1.0.0
   */
  public static boolean isValidAddress(final String stringAddress) {
    Validate.notIllegalArgument(
        !Strings.blank(stringAddress), "Address must be not empty or blank.");
    return Pattern.matches("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", stringAddress);
  }

  /**
   * Validate string mac address.
   *
   * @param stringAddress string mac address.
   * @return a {@code boolean} indicating if the stringAddress is a valid mac address; or false
   *     otherwise.
   * @since 1.5.0
   */
  public static boolean isValidString(final String stringAddress) {
    final int separator = separator0(stringAddress);
    if (separator < 0) {
      return false;
    }
    assert stringAddress != null;
    final int length = stringAddress.length();
    for (int i = 0; i < length; i += separator) {
      final int hi = Hexs.decodeHexNibble(stringAddress.charAt(i));
      final int lo = Hexs.decodeHexNibble(stringAddress.charAt(i + 1));
      if (hi == -1 || lo == -1) {
        return false;
      }
    }
    return true;
  }

  /**
   * Returns length of MAC Address.
   *
   * @return MAC Address length.
   * @since 1.0.0
   */
  public int length() {
    return this.address.length;
  }

  /**
   * Returning long MAC Address.
   *
   * @return long MAC Address.
   * @since 1.0.0
   */
  public long toLong() {
    long addr = 0;
    for (int i = 0; i < MAC_ADDRESS_LENGTH; i++) {
      long tmp = (this.address[i] & 0xffL) << (5 - i) * 8;
      addr |= tmp;
    }
    return addr;
  }

  /**
   * Return true if Broadcast MAC Address.
   *
   * @return true if Broadcast MAC Address, false otherwise.
   * @since 1.0.0
   */
  public boolean isBroadcast() {
    for (final byte b : this.address) {
      if (b != -1) {
        return false;
      }
    }
    return true;
  }

  /**
   * Return true if Multicast MAC Address.
   *
   * @return true if Multicast MAC Address, false otherwise.
   * @since 1.0.0
   */
  public boolean isMulticast() {
    if (this.isBroadcast()) {
      return false;
    }
    return (this.address[0] & 1) != 0;
  }

  /**
   * @return returns true if the MAC address represented by this object is a globally unique
   *     address; otherwise false.
   * @since 1.0.0
   */
  public boolean isGloballyUnique() {
    return (address[0] & 2) == 0;
  }

  /**
   * @return true if the MAC address represented by this object is a unicast address; otherwise
   *     false.
   * @since 1.0.0
   */
  public boolean isUnicast() {
    return (address[0] & 1) == 0;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    MacAddress that = (MacAddress) o;

    return Arrays.equals(address, that.address);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(address);
  }

  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder(17);
    sb.append(Strings.hex(address[0]));
    for (int i = 1; i < MAC_ADDRESS_LENGTH; i++) {
      sb.append(':');
      sb.append(Strings.hex(address[i]));
    }
    return sb.toString();
  }

  /**
   * Returns bytes Mac Address.
   *
   * @return returns bytes Mas Address.
   * @since 1.0.0
   */
  public byte[] address() {
    return Arrays.copyOf(this.address, this.address.length);
  }
}
