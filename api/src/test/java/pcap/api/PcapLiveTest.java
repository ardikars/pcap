package pcap.api;

import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import pcap.common.logging.Logger;
import pcap.common.logging.LoggerFactory;
import pcap.spi.Interface;
import pcap.spi.Status;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.*;

public class PcapLiveTest {

  private static final Logger LOGGER = LoggerFactory.getLogger(PcapLiveTest.class);

  private static final int MAX_PACKET = 10;
  private static final String FILTER = "ip";

  @Test
  public void lookupInterfaceTest() throws ErrorException {
    Interface source = Pcaps.lookupInterface();
    Assertions.assertNotNull(source);
  }

  @Test
  public void liveTest()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Interface source = Pcaps.lookupInterface();
    Assertions.assertNotNull(source);
    Pcap pcap = Pcaps.live(new PcapLive(source));
    Assertions.assertNotNull(pcap);
    pcap.close();
  }

  @Test
  public void liveLoopTest()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Interface source = Pcaps.lookupInterface();
    Assertions.assertNotNull(source);
    Pcap pcap = Pcaps.live(new PcapLive(source));
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
  public void liveStatusTest()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Interface source = Pcaps.lookupInterface();
    Assertions.assertNotNull(source);
    Pcap pcap = Pcaps.live(new PcapLive(source));
    Assertions.assertNotNull(pcap);
    try {
      pcap.loop(
          MAX_PACKET,
          (args, header, buffer) -> {
            Assertions.assertEquals(args, MAX_PACKET);
            Assertions.assertNotNull(header);
            Assertions.assertNotNull(buffer);
            try {
              Status status = pcap.status();
              Assertions.assertNotNull(status);
            } catch (ErrorException e) {
              LOGGER.warn(e);
            }
          },
          MAX_PACKET);
    } catch (BreakException e) {
      LOGGER.warn(e);
    }
    pcap.close();
  }

  @Test
  public void liveFilterTest()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Interface source = Pcaps.lookupInterface();
    Assertions.assertNotNull(source);
    Pcap pcap = Pcaps.live(new PcapLive(source));
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
  public void liveLoopBreakTest()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Interface source = Pcaps.lookupInterface();
    Assertions.assertNotNull(source);
    Pcap pcap = Pcaps.live(new PcapLive(source));
    Assertions.assertNotNull(pcap);
    AtomicInteger counter = new AtomicInteger();
    try {
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
