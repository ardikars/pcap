/** This code is licenced under the GPL version 2. */
package pcap.common.memory.internal;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.common.internal.UnsafeHelper;
import pcap.common.util.Platforms;

@RunWith(JUnitPlatform.class)
public class UnsafeHelperTest {

  // @Test
  public void isUnsafeAvailableTest() {
    if (Platforms.javaMojorVersion() > 8) {
      assert !UnsafeHelper.isUnsafeAvailable();
    } else {
      assert UnsafeHelper.isUnsafeAvailable();
    }
  }

  @Test
  public void isUnalignedTest() {
    assert UnsafeHelper.isUnaligned() || !UnsafeHelper.isUnaligned();
  }

  @Test
  public void getUnsafeTest() {
    try {
      assert UnsafeHelper.getUnsafe() != null;
    } catch (UnsupportedOperationException ex) {
      assert Platforms.javaMojorVersion() > 8;
    }
  }

  @Test
  public void getNoUnsafeCausesTest() {
    List<Throwable> throwables = UnsafeHelper.getNoUnsafeCauses();
    if (Platforms.javaMojorVersion() > 8) {
      assert !throwables.isEmpty();
    } else {
      assert throwables.isEmpty();
    }
  }
}
