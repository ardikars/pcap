package pcap.api;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import pcap.spi.Timestamp;

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
