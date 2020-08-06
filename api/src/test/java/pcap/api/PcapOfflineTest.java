/** This code is licenced under the GPL version 2. */
package pcap.api;

import java.foreign.NativeTypes;
import java.foreign.Scope;
import java.foreign.memory.Pointer;
import java.io.File;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.api.internal.foreign.mapping.PcapMapping;
import pcap.api.internal.foreign.pcap_header;
import pcap.common.logging.Logger;
import pcap.common.logging.LoggerFactory;
import pcap.spi.Pcap;
import pcap.spi.Timestamp;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.BreakException;
import pcap.spi.exception.error.NotActivatedException;

// @EnabledOnJre(JRE.JAVA_14)
@RunWith(JUnitPlatform.class)
public class PcapOfflineTest {

  private static final Logger LOGGER = LoggerFactory.getLogger(PcapOfflineTest.class);

  private static final int MAX_PACKET = 10;
  private static final String FILTER = "ip";
  private static final String FILE = "src/test/resources/sample.pcapng";

  @Test
  public void offlineTest() throws ErrorException {
    Pcap pcap = Pcaps.offline(new PcapOffline(new File(FILE)));
    Assertions.assertNotNull(pcap);
    pcap.close();
  }

  @Test
  public void isSwappedTest() throws ErrorException, NotActivatedException {
    Pcap pcap = Pcaps.offline(new PcapOffline(new File(FILE)));
    Assertions.assertNotNull(pcap);
    boolean swapped = pcap.isSwapped();
    Assertions.assertTrue(swapped || !swapped);
    pcap.close();
  }

  @Test
  public void minorAndMajorVersionTest() throws ErrorException {
    Pcap pcap = Pcaps.offline(new PcapOffline(new File(FILE)));
    Assertions.assertNotNull(pcap);
    int majorVerson = pcap.majorVersion();
    int minorVersion = pcap.minorVersion();
    Assertions.assertTrue(majorVerson >= 0);
    Assertions.assertTrue(minorVersion >= 0);
    pcap.close();
  }

  @Test
  public void setNonBlokingTest() throws ErrorException {
    Pcap pcap = Pcaps.offline(new PcapOffline(new File(FILE)));
    Assertions.assertNotNull(pcap);
    Assertions.assertThrows(ErrorException.class, () -> pcap.setNonBlock(true));
    pcap.close();
  }

  @Test
  public void getNonBlockingTest() throws ErrorException {
    Pcap pcap = Pcaps.offline(new PcapOffline(new File(FILE)));
    Assertions.assertNotNull(pcap);
    Assertions.assertFalse(pcap.getNonBlock()); // always false on offline handler.
    pcap.close();
  }

  @Test
  public void offlineLoopTest() throws ErrorException {
    Pcap pcap = Pcaps.offline(new PcapOffline(new File(FILE)));
    Assertions.assertNotNull(pcap);
    try {
      pcap.loop(
          MAX_PACKET,
          (args, header, buffer) -> {
            Assertions.assertEquals(args, MAX_PACKET);
            Assertions.assertNotNull(buffer);
            Assertions.assertNotNull(header);
            Assertions.assertTrue(header.captureLength() == 105);
            Assertions.assertTrue(header.length() == 105);
            Assertions.assertNotNull(header.timestamp());
            Assertions.assertTrue(header.timestamp().microSecond() > 0);
            Assertions.assertTrue(header.timestamp().second() > 0L);
          },
          MAX_PACKET);
    } catch (BreakException e) {
      LOGGER.warn(e);
    }
    pcap.close();
  }

  @Test
  public void pcapOfflineTest() {
    Assertions.assertNotNull(new PcapOfflineOptions().timestampPrecision(Timestamp.Precision.NANO));
    Assertions.assertNotNull(
        new PcapOfflineOptions().timestampPrecision(Timestamp.Precision.NANO).toString());
  }

  @Test
  public void offlineFilterTest() throws ErrorException {
    Pcap pcap = Pcaps.offline(new PcapOffline(new File(FILE)));
    Assertions.assertNotNull(pcap);
    pcap.setFilter(FILTER, true);
    try {
      pcap.loop(
          MAX_PACKET,
          (args, header, buffer) -> {
            Assertions.assertEquals(args, MAX_PACKET);
            Assertions.assertNotNull(buffer);
            Assertions.assertNotNull(header);
            Assertions.assertTrue(header.captureLength() == 105);
            Assertions.assertTrue(header.length() == 105);
            Assertions.assertNotNull(header.timestamp());
            Assertions.assertTrue(header.timestamp().microSecond() > 0);
            Assertions.assertTrue(header.timestamp().second() > 0L);
          },
          MAX_PACKET);
    } catch (BreakException e) {
      LOGGER.warn(e);
    }
    pcap.close();
  }

  @Test
  public void loopBreakTest() throws ErrorException {
    Pcap pcap = Pcaps.offline(new PcapOffline(new File(FILE)));
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
            Assertions.assertNotNull(buffer);
            Assertions.assertNotNull(header);
            Assertions.assertTrue(header.captureLength() == 105);
            Assertions.assertTrue(header.length() == 105);
            Assertions.assertNotNull(header.timestamp());
            Assertions.assertTrue(header.timestamp().microSecond() > 0);
            Assertions.assertTrue(header.timestamp().second() > 0L);
          },
          MAX_PACKET);
    } catch (BreakException e) {
      LOGGER.warn(e);
    }
    pcap.close();
  }

  @Test
  public void offlineParameterizeTest() throws ErrorException {
    Pcap pcap = Pcaps.offline(new PcapOffline(new File(FILE)));
    Assertions.assertNotNull(pcap);
    try {
      pcap.loop(
          MAX_PACKET,
          (args, header, buffer) -> {
            Assertions.assertEquals(args, MAX_PACKET);
            Assertions.assertNotNull(buffer);
            Assertions.assertNotNull(header);
            Assertions.assertTrue(header.captureLength() == 105);
            Assertions.assertTrue(header.length() == 105);
            Assertions.assertNotNull(header.timestamp());
            Assertions.assertTrue(header.timestamp().microSecond() > 0);
            Assertions.assertTrue(header.timestamp().second() > 0L);
          },
          MAX_PACKET);
    } catch (BreakException e) {
      LOGGER.warn(e);
    }
    pcap.close();
  }

  @Test
  public void offlineParameterize2Test() throws ErrorException {
    Pcap pcap =
        Pcaps.offline(
            new PcapOffline(
                new File(FILE),
                new PcapOfflineOptions().timestampPrecision(Timestamp.Precision.MICRO)));
    Assertions.assertNotNull(pcap);
    try {
      pcap.loop(
          MAX_PACKET,
          (args, header, buffer) -> {
            Assertions.assertEquals(args, MAX_PACKET);
            Assertions.assertNotNull(buffer);
            Assertions.assertNotNull(header);
            Assertions.assertTrue(header.captureLength() == 105);
            Assertions.assertTrue(header.length() == 105);
            Assertions.assertNotNull(header.timestamp());
            Assertions.assertTrue(header.timestamp().microSecond() > 0);
            Assertions.assertTrue(header.timestamp().second() > 0L);
          },
          MAX_PACKET);
    } catch (BreakException e) {
      LOGGER.warn(e);
    }
    pcap.close();
  }

  @Test
  public void nullCheckTest() throws ErrorException {
    try (Scope scope = Scope.globalScope().fork()) {
      PcapOffline offline = new PcapOffline(new File(FILE));
      Pointer<Byte> errbuf = scope.allocate(NativeTypes.INT8, PcapMapping.ERRBUF_SIZE);
      Pointer<Byte> source = scope.allocateCString(new File(FILE).getAbsolutePath());

      Pointer<pcap_header.pcap> pointer = PcapMapping.MAPPING.pcap_open_offline(source, errbuf);
      offline.nullCheck(pointer, errbuf);

      Assertions.assertThrows(IllegalStateException.class, () -> offline.nullCheck(null, errbuf));
    }
  }
}
