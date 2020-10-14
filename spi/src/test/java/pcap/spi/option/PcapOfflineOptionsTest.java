package pcap.spi.option;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.spi.Timestamp;

@RunWith(JUnitPlatform.class)
public class PcapOfflineOptionsTest {

  @Test
  void setAndGetOptionsTest() {
    Timestamp.Precision tsPrecision = Timestamp.Precision.MICRO;
    DefaultOfflineOptions options = new DefaultOfflineOptions();
    options.timestampPrecision(tsPrecision);
    Assertions.assertEquals(tsPrecision, options.timestampPrecision());
    Assertions.assertNotNull(options.toString());
  }
}
