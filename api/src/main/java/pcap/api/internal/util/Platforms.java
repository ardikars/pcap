package pcap.api.internal.util;

/** This code is licenced under the GPL version 2. */
import pcap.common.annotation.Inclubating;
import pcap.common.util.Properties;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public final class Platforms {

  private static final Name NAME;

  static {
    final String osName = Properties.getProperty("os.name").toUpperCase().trim();
    if (osName.startsWith("LINUX")) {
      NAME = Name.LINUX;
    } else if (osName.startsWith("WINDOWS")) {
      NAME = Name.WINDOWS;
    } else if (osName.startsWith("MAC OS")) {
      NAME = Name.DARWIN;
    } else {
      NAME = Name.UNKNOWN;
    }
  }

  private Platforms() {}

  /**
   * Get platform name.
   *
   * @return returns platform name.
   */
  public static Name name() {
    return NAME;
  }

  /**
   * Returns true if Windows platform, false otherwise.
   *
   * @return returns true if windows platform, false otherwise.
   */
  public static boolean isWindows() {
    return NAME == Name.WINDOWS;
  }

  /**
   * Returns true if Linux platform, false otherwise.
   *
   * @return returns true if linux platform, false otherwise.
   */
  public static boolean isLinux() {
    return NAME == Name.LINUX;
  }

  /**
   * Returns true if Darwin (MacOs) platform, false otherwise.
   *
   * @return returns true if Darwin (MacOs) platform, false otherwise.
   */
  public static boolean isDarwin() {
    return NAME == Name.DARWIN;
  }

  public enum Name {
    WINDOWS,
    LINUX,
    DARWIN,
    UNKNOWN
  }
}
