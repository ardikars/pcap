package pcap.api;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnJre;
import org.junit.jupiter.api.condition.JRE;

@EnabledOnJre(JRE.JAVA_14)
// @RunWith(JUnitPlatform.class)
public class PcapsTest {

  @Test
  public void versionTest() {
    Assertions.assertNotNull(Pcaps.version());
  }
}
