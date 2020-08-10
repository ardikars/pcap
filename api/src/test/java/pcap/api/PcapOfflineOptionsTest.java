package pcap.api;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.spi.Timestamp;

@RunWith(JUnitPlatform.class)
public class PcapOfflineOptionsTest {

  @Test
  public void setAndGetOptionsTest() {
    Timestamp.Precision tsPrecision = Timestamp.Precision.MICRO;
    PcapOfflineOptions options = new PcapOfflineOptions();
    options.timestampPrecision(tsPrecision);
    Assertions.assertEquals(tsPrecision, options.timestampPrecision());
    Assertions.assertNotNull(options.toString());
  }
}
