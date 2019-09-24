package pcap.api;

import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import pcap.common.logging.Logger;
import pcap.common.logging.LoggerFactory;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.BreakException;

public class PcapOfflineTest {

  private static final Logger LOGGER = LoggerFactory.getLogger(PcapOfflineTest.class);

  private static final int MAX_PACKET = 10;
  private static final String FILTER = "ip";
  private static final String FILE = "../.resources/sample.pcapng";

  @Test
  public void offlineTest() throws ErrorException {
    Pcap pcap = Pcaps.offline(new PcapOffline(FILE));
    Assertions.assertNotNull(pcap);
    pcap.close();
  }

  @Test
  public void offlineLoopTest() throws ErrorException {
    Pcap pcap = Pcaps.offline(new PcapOffline(FILE));
    Assertions.assertNotNull(pcap);
    try {
      pcap.loop(
          MAX_PACKET,
          (args, header, buffer) -> {
            Assertions.assertEquals(args, MAX_PACKET);
            Assertions.assertNotNull(header);
            Assertions.assertNotNull(buffer);
          },
          MAX_PACKET);
    } catch (BreakException e) {
      LOGGER.warn(e);
    }
    pcap.close();
  }

  @Test
  public void offlineFilterTest() throws ErrorException {
    Pcap pcap = Pcaps.offline(new PcapOffline(FILE));
    Assertions.assertNotNull(pcap);
    pcap.setFilter(FILTER, true);
    try {
      pcap.loop(
          MAX_PACKET,
          (args, header, buffer) -> {
            Assertions.assertEquals(args, MAX_PACKET);
            Assertions.assertNotNull(header);
            Assertions.assertNotNull(buffer);
          },
          MAX_PACKET);
    } catch (BreakException e) {
      LOGGER.warn(e);
    }
    pcap.close();
  }

  @Test
  public void liveLoopBreakTest() throws ErrorException {
    Pcap pcap = Pcaps.offline(new PcapOffline(FILE));
    Assertions.assertNotNull(pcap);
    try {
      AtomicInteger counter = new AtomicInteger();
      pcap.loop(
          MAX_PACKET,
          (args, header, buffer) -> {
            if (counter.incrementAndGet() == args / 2) {
              pcap.breakLoop();
            }
            Assertions.assertEquals(args, MAX_PACKET);
            Assertions.assertNotNull(header);
            Assertions.assertNotNull(buffer);
          },
          MAX_PACKET);
    } catch (BreakException e) {
      LOGGER.warn(e);
    }
    pcap.close();
  }
}
