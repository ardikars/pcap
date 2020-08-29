package pcap.api.internal.util;

import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@RunWith(JUnitPlatform.class)
public class PlatformsTest {

  public void getNameTest(String name) {
    assert Platforms.name().name().equals(name);
  }

  public void isWindowsTest(boolean windows) {
    assert Platforms.isWindows() == windows;
  }

  public void isLinuxTest(boolean linux) {
    assert Platforms.isLinux() == linux;
  }

  public void isDarwinTest(boolean darwin) {
    assert Platforms.isDarwin() == darwin;
  }

  @Test
  public void platformTest() {
    switch (Platforms.name()) {
      case DARWIN:
        doMacOsTest();
        break;
      case LINUX:
        doLinuxTest();
        break;
      case WINDOWS:
        doWindowsTest();
        break;
      default:
        doUnknownTest();
    }
  }

  void doLinuxTest() {
    getNameTest("LINUX");
    isWindowsTest(false);
    isLinuxTest(true);
    isDarwinTest(false);
  }

  void doMacOsTest() {
    getNameTest("DARWIN");
    isWindowsTest(false);
    isLinuxTest(false);
    isDarwinTest(true);
  }

  void doWindowsTest() {
    getNameTest("WINDOWS");
    isWindowsTest(true);
    isLinuxTest(false);
    isDarwinTest(false);
  }

  void doUnknownTest() {
    getNameTest("UNKNOWN");
    isWindowsTest(false);
    isLinuxTest(false);
    isDarwinTest(false);
  }
}
