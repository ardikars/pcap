/** This code is licenced under the GPL version 2. */
package pcap.common.net;

import java.net.UnknownHostException;
import java.util.Arrays;
import pcap.common.annotation.Inclubating;
import pcap.common.util.Longs;
import pcap.common.util.Validate;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public final class Inet6Address extends InetAddress {

  /** Zero IPv6 Address. */
  public static final Inet6Address ZERO =
      valueOf(
          new byte[] {
            (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0,
            (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0,
            (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0,
            (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0,
          });

  /** IPv6 Loopback Address (::1). */
  public static final Inet6Address LOCALHOST = valueOf("::1");

  /** IPv6 Address Length. */
  public static final short IPV6_ADDRESS_LENGTH = 16;

  private byte[] address;

  private Inet6Address(byte[] address) {
    Validate.nullPointer(address);
    Validate.notIllegalArgument(address.length == IPV6_ADDRESS_LENGTH);
    this.address = address;
  }

  /**
   * Determines the IPv6 address.
   *
   * @param bytesAddress ipv6 bytesAddress address.
   * @return an IPv6 address.
   */
  public static Inet6Address valueOf(final byte[] bytesAddress) {
    return new Inet6Address(bytesAddress);
  }

  /**
   * Determines the IPv6 address.
   *
   * @param stringAddress ipv6 stringAddress address.
   * @return an IPv6 address.
   */
  public static Inet6Address valueOf(String stringAddress) {
    try {
      return new Inet6Address(java.net.Inet6Address.getByName(stringAddress).getAddress());
    } catch (UnknownHostException e) {
      throw new IllegalArgumentException("Invalid ipv6 address.");
    }
  }

  /**
   * @see <a
   *     href="https://www.iana.org/assignments/ipv6-multicast-addresses/ipv6-multicast-addresses.xhtml">IPV6
   *     Multicast Address</a>
   * @return returns {@code true} if multicast address, {@code false } otherwise.
   */
  @Override
  public boolean isMulticastAddress() {
    return ((address[0] & 0xff) == 0xff);
  }

  @Override
  public boolean isAnyLocalAddress() {
    byte test = 0x00;
    for (int i = 0; i < Inet6Address.IPV6_ADDRESS_LENGTH; i++) {
      test |= address[i];
    }
    return (test == 0x00);
  }

  @Override
  public boolean isLoopbackAddress() {
    byte test = 0x00;
    for (int i = 0; i < 15; i++) {
      test |= address[i];
    }
    return (test == 0x00) && (address[15] == 0x01);
  }

  @Override
  public boolean isLinkLocalAddress() {
    return ((address[0] & 0xff) == 0xfe && (address[1] & 0xc0) == 0x80);
  }

  @Override
  public boolean isSiteLocalAddress() {
    return ((address[0] & 0xff) == 0xfe && (address[1] & 0xc0) == 0xc0);
  }

  @Override
  public boolean isMcGlobal() {
    return ((address[0] & 0xff) == 0xff && (address[1] & 0x0f) == 0x0e);
  }

  @Override
  public boolean isMcNodeLocal() {
    return ((address[0] & 0xff) == 0xff && (address[1] & 0x0f) == 0x01);
  }

  @Override
  public boolean isMcLinkLocal() {
    return ((address[0] & 0xff) == 0xff && (address[1] & 0x0f) == 0x02);
  }

  @Override
  public boolean isMcSiteLocal() {
    return ((address[0] & 0xff) == 0xff && (address[1] & 0x0f) == 0x05);
  }

  @Override
  public boolean isMcOrgLocal() {
    return ((address[0] & 0xff) == 0xff && (address[1] & 0x0f) == 0x08);
  }

  /**
   * Returns {@code long} address.
   *
   * @return returns {@code long} address.
   */
  public long toLong() {
    return Longs.toLong(address);
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    Inet6Address that = (Inet6Address) o;

    return Arrays.equals(address, that.address);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(address);
  }

  /**
   * returns ipv6 string.
   *
   * @return ipv6 string.
   */
  @Override
  public String toString() {
    byte[] bytes = address;
    int[] hextets = new int[8];
    for (int i = 0; i < hextets.length; i++) {
      hextets[i] =
          0 << 24 | (0 & 0xFF) << 16 | (bytes[2 * i] & 0xFF) << 8 | (bytes[2 * i + 1] & 0xFF);
    }
    int bestRunStart = -1;
    int bestRunLength = -1;
    int runStart = -1;
    for (int i = 0; i < hextets.length + 1; i++) {
      if (i < hextets.length && hextets[i] == 0) {
        if (runStart < 0) {
          runStart = i;
        }
      } else if (runStart >= 0) {
        int runLength = i - runStart;
        if (runLength > bestRunLength) {
          bestRunStart = runStart;
          bestRunLength = runLength;
        }
        runStart = -1;
      }
    }
    if (bestRunLength >= 2) {
      Arrays.fill(hextets, bestRunStart, bestRunStart + bestRunLength, -1);
    }
    StringBuilder buf = new StringBuilder(39);
    boolean lastWasNumber = false;
    for (int i = 0; i < hextets.length; i++) {
      boolean thisIsNumber = hextets[i] >= 0;
      if (thisIsNumber) {
        if (lastWasNumber) {
          buf.append(':');
        }
        buf.append(Integer.toHexString(hextets[i]));
      } else {
        if (i == 0 || lastWasNumber) {
          buf.append("::");
        }
      }
      lastWasNumber = thisIsNumber;
    }
    return buf.toString();
  }

  /**
   * Returns the raw IPv6 address of this {@code Inet6Address} object.
   *
   * @return the raw IPv6 address of this object.
   */
  @Override
  public byte[] address() {
    return Arrays.copyOf(this.address, this.address.length);
  }
}
