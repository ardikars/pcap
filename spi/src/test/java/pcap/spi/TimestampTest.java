package pcap.spi;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
public class TimestampTest {

  @Test
  public void typeTest() {
    Assertions.assertEquals(0, Timestamp.Type.HOST.value());
    Assertions.assertEquals(1, Timestamp.Type.HOST_LOWPREC.value());
    Assertions.assertEquals(2, Timestamp.Type.HOST_HIPREC.value());
    Assertions.assertEquals(3, Timestamp.Type.ADAPTER.value());
    Assertions.assertEquals(4, Timestamp.Type.ADAPTER_UNSYNCED.value());
  }

  @Test
  public void precisionTest() {
    Assertions.assertEquals(0, Timestamp.Precision.MICRO.value());
    Assertions.assertEquals(1, Timestamp.Precision.NANO.value());
  }
}
