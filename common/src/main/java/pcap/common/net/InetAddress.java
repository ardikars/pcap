/** This code is licenced under the GPL version 2. */
package pcap.common.net;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
public abstract class InetAddress implements Address {

  /**
   * Determines the IPv4 or IPv6 address.
   *
   * @param stringAddress ipv4 or ipv6 string address.
   * @return an IPv4 or IPv6 address.
   */
  public static InetAddress valueOf(String stringAddress) {
    if (stringAddress.contains(":")) {
      return Inet6Address.valueOf(stringAddress);
    } else {
      return Inet4Address.valueOf(stringAddress);
    }
  }

  /**
   * Validate given ip string address.
   *
   * @param stringAddress ipv4 or ipv6 string address.
   * @return a {@code boolean} indicating if the stringAddress is a valid ip address; or false
   *     otherwise.
   */
  public static boolean isValidAddress(String stringAddress) {
    try {
      valueOf(stringAddress);
      return true;
    } catch (Exception e) {
      return false;
    }
  }

  protected abstract boolean isMulticastAddress();

  protected abstract boolean isAnyLocalAddress();

  protected abstract boolean isLoopbackAddress();

  protected abstract boolean isLinkLocalAddress();

  protected abstract boolean isSiteLocalAddress();

  protected abstract boolean isMcGlobal();

  protected abstract boolean isMcNodeLocal();

  protected abstract boolean isMcLinkLocal();

  protected abstract boolean isMcSiteLocal();

  protected abstract boolean isMcOrgLocal();
}
