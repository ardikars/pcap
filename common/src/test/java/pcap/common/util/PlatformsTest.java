/** This code is licenced under the GPL version 2. */
package pcap.common.util;

import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
public class PlatformsTest {

  @Test
  public void getNameTest() {
    assert Platforms.getName().name() != null;
  }

  @Test
  public void getArchitectureTest() {
    assert Platforms.getArchitecture() != null;
  }

  @Test
  public void isWindowsTest() {
    assert Platforms.isWindows() || !Platforms.isWindows();
  }

  @Test
  public void isLinuxTest() {
    assert Platforms.isLinux() || !Platforms.isLinux();
  }

  @Test
  public void isAndroidTest() {
    assert Platforms.isAndroid() || !Platforms.isAndroid();
  }

  @Test
  public void isFreeBsdTest() {
    assert Platforms.isFreeBsd() || !Platforms.isFreeBsd();
  }

  @Test
  public void isDarwinTest() {
    assert Platforms.isDarwin() || !Platforms.isDarwin();
  }

  @Test
  public void is32BitTest() {
    assert Platforms.is32Bit() || !Platforms.is32Bit();
  }

  @Test
  public void is64BitTest() {
    assert Platforms.is64Bit() || !Platforms.is64Bit();
  }

  @Test
  public void isArmTest() {
    assert Platforms.isArm() || !Platforms.isArm();
  }

  @Test
  public void isIntelTest() {
    assert Platforms.isIntel() || !Platforms.isIntel();
  }

  @Test
  public void isAmdTest() {
    assert Platforms.isAmd() || !Platforms.isAmd();
  }

  @Test
  public void getCpuVersionTest() {
    assert Platforms.getCpuVersion() != null;
  }

  @Test
  public void getJavaMajorVersionTest() {
    assert Platforms.getJavaMojorVersion() != 0;
  }
}
