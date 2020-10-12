/** This code is licenced under the GPL version 2. */
package pcap.common.net;

import java.util.Arrays;
import pcap.common.util.Validate;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
public final class Inet4Address extends InetAddress {

  /** IPv4 Any local address (0.0.0.0). */
  public static final Inet4Address ZERO = valueOf(0);
  /** IPv4 Address Length. */
  public static final int IPV4_ADDRESS_LENGTH = 4;
  /** IPv4 Loopback address (127.0.0.1). */
  public static final Inet4Address LOCALHOST = valueOf("127.0.0.1");

  private final byte[] address;

  private Inet4Address(final byte[] address) {
    Validate.nullPointer(address);
    Validate.notIllegalArgument(address.length == IPV4_ADDRESS_LENGTH);
    this.address = address;
  }

  /**
   * Determines the IPv4 address.
   *
   * @param stringAddress ipv4 string address.
   * @return an IPv4 address.
   */
  public static Inet4Address valueOf(String stringAddress) {
    String[] parts = stringAddress.split("\\.");
    byte[] result = new byte[parts.length];
    Validate.notIllegalArgument(result.length == IPV4_ADDRESS_LENGTH);
    for (int i = 0; i < result.length; i++) {
      Validate.notIllegalArgument(
          !(parts[i].length() > 1 && parts[i].startsWith("0")),
          "Number must be not started with '9' (" + parts[i] + ")");
      int value = Integer.valueOf(parts[i]).intValue();
      Validate.notIllegalArgument(value <= 0xFF, "To large number (" + value + ").");
      result[i] = Integer.valueOf(parts[i]).byteValue();
    }
    return Inet4Address.valueOf(result);
  }

  /**
   * Determines the IPv4 address.
   *
   * @param bytesAddress ipv4 bytes address.
   * @return an IPv4 address.
   */
  public static Inet4Address valueOf(final byte[] bytesAddress) {
    return new Inet4Address(bytesAddress);
  }

  /**
   * Determines the IPv4 address.
   *
   * @param intAddress ipv4 int address.
   * @return an IPv4 address.
   */
  public static Inet4Address valueOf(final int intAddress) {
    return new Inet4Address(
        new byte[] {
          (byte) (intAddress >>> 24),
          (byte) (intAddress >>> 16),
          (byte) (intAddress >>> 8),
          (byte) intAddress
        });
  }

  /**
   * Check whether ip is multicast address.
   *
   * @see <a
   *     href="https://www.iana.org/assignments/multicast-addresses/multicast-addresses.xhtml">Muslticast
   *     address.</a>
   * @return returns {@code true} if multicast, {@code false} otherwise.
   */
  @Override
  public boolean isMulticastAddress() {
    return (toInt() & 0xf0000000) == 0xe0000000;
  }

  /**
   * Check whether ip is any local address (0.0.0.0).
   *
   * @return @return returns {@code true} if any local address, {@code false} otherwise.
   */
  @Override
  public boolean isAnyLocalAddress() {
    return toInt() == 0;
  }

  /**
   * Returns true if address is 127.x.x.x, false otherwise.
   *
   * @return returns true if loopback address, false otherwise.
   */
  @Override
  public boolean isLoopbackAddress() {
    return (address[0] & 0xff) == 127;
  }

  @Override
  public boolean isLinkLocalAddress() {
    return (address[0] & 0xff) == 169 && (address[1] & 0xff) == 254;
  }

  /** refer to RFC 1918 10/8 prefix 172.16/12 prefix 192.168/16 prefix */
  @Override
  public boolean isSiteLocalAddress() {
    return (address[0] & 0xff) == 10
        || (address[0] & 0xff) == 172 && (address[1] & 0xff) == 16
        || (address[0] & 0xff) == 192 && (address[1] & 0xff) == 168;
  }

  /** 224.0.1.0 to 238.255.255.255 */
  @Override
  public boolean isMcGlobal() {
    return ((address[0] & 0xff) >= 224 && (address[0] & 0xff) <= 238)
        && !((address[0] & 0xff) == 224 && address[1] == 0 && address[2] == 0);
  }

  /** Unless ttl == 0 */
  @Override
  public boolean isMcNodeLocal() {
    return false;
  }

  /** 224.0.0/24 prefix and ttl == 1 */
  @Override
  public boolean isMcLinkLocal() {
    return (address[0] & 0xff) == 224 && (address[1] & 0xff) == 0 && (address[2] & 0xff) == 0;
  }

  /** 239.255/16 prefix or ttl &lt; 32 */
  @Override
  public boolean isMcSiteLocal() {
    return (address[0] & 0xff) == 239 && (address[1] & 0xff) == 255;
  }

  /** 239.192 - 239.195 */
  @Override
  public boolean isMcOrgLocal() {
    return (address[0] & 0xff) == 239 && (address[1] & 0xff) >= 192 && (address[1] & 0xff) <= 195;
  }

  /**
   * Returns the int IPv4 address of this {@code Inet4Address} object.
   *
   * @return the int IPv4 address of this object.
   */
  public int toInt() {
    int ip = 0;
    for (int i = 0; i < Inet4Address.IPV4_ADDRESS_LENGTH; i++) {
      final int t = (this.address[i] & 0xff) << (3 - i) * 8;
      ip |= t;
    }
    return ip;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    Inet4Address that = (Inet4Address) o;
    return Arrays.equals(address, that.address);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(address);
  }

  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder();
    sb.append(this.address[0] & 0xff).append(".");
    sb.append(this.address[1] & 0xff).append(".");
    sb.append(this.address[2] & 0xff).append(".");
    sb.append(this.address[3] & 0xff);
    return sb.toString();
  }

  /**
   * Returns the raw IPv4 address of this {@code Inet4Address} object. The result is in network byte
   * order: the highest order byte of the address is in {@code toBytes()[0]}.
   *
   * @return the raw IPv4 address of this object.
   */
  @Override
  public byte[] address() {
    return Arrays.copyOf(this.address, this.address.length);
  }
}
