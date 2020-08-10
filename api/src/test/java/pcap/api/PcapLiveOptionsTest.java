package pcap.api;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import pcap.spi.Timestamp;

public class PcapLiveOptionsTest {

  @Test
  public void setAndGetOptionsTest() {
    int snapshotLength = 2048;
    boolean promiscuous = true;
    boolean rfmon = false;
    boolean immediate = true;
    int timeout = 2000;
    int bufferSize = 4096;
    Timestamp.Type tsType = Timestamp.Type.HOST;
    Timestamp.Precision tsPrecision = Timestamp.Precision.MICRO;
    PcapLiveOptions options = new PcapLiveOptions();
    options.snapshotLength(snapshotLength);
    options.promiscuous(promiscuous);
    options.rfmon(rfmon);
    options.timeout(timeout);
    options.timestampType(tsType);
    options.timestampPrecision(tsPrecision);
    options.immediate(immediate);
    options.bufferSize(bufferSize);
    Assertions.assertEquals(snapshotLength, options.snapshotLength());
    Assertions.assertEquals(promiscuous, options.isPromiscuous());
    Assertions.assertEquals(rfmon, options.isRfmon());
    Assertions.assertEquals(timeout, options.timeout());
    Assertions.assertEquals(tsType, options.timestampType());
    Assertions.assertEquals(tsPrecision, options.timestampPrecision());
    Assertions.assertEquals(immediate, options.isImmediate());
    Assertions.assertEquals(bufferSize, options.bufferSize());
    Assertions.assertNotNull(options.toString());
  }

  @Test
  public void timestampOptionsTest() {
    System.setProperty("pcap.timestampType", "HOST");
    System.setProperty("pcap.timestampPrecision", "NANO");
    PcapLiveOptions configuredOptions = new PcapLiveOptions();
    Assertions.assertNotNull(configuredOptions);
    Assertions.assertEquals(Timestamp.Type.HOST, configuredOptions.timestampType());
    Assertions.assertEquals(Timestamp.Precision.NANO, configuredOptions.timestampPrecision());

    System.clearProperty("pcap.timestampType");
    System.clearProperty("pcap.timestampPrecision");
    PcapLiveOptions defaultOptions = new PcapLiveOptions();
    Assertions.assertNotNull(defaultOptions);
    Assertions.assertNull(defaultOptions.timestampType());
    Assertions.assertEquals(Timestamp.Precision.MICRO, defaultOptions.timestampPrecision());
  }
}
