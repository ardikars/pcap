/** This code is licenced under the GPL version 2. */
package pcap.api;

import java.util.Iterator;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.common.logging.Logger;
import pcap.common.logging.LoggerFactory;
import pcap.spi.*;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.*;

// @EnabledOnJre(JRE.JAVA_14)
@RunWith(JUnitPlatform.class)
public class PcapLiveTest {

  private static final Logger LOGGER = LoggerFactory.getLogger(PcapLiveTest.class);

  private static final int MAX_PACKET = 10;
  private static final String FILTER = "ip";

  @Test
  public void iterateInterfaceTest() throws ErrorException {
    Interface aInterface = Pcaps.lookupInterfaces();
    Iterator<Interface> interfaceIterator = aInterface.iterator();
    while (interfaceIterator.hasNext()) {
      Interface nextInterface = interfaceIterator.next();
      Assertions.assertNotNull(nextInterface);
      Assertions.assertNotNull(nextInterface.name());
      Assertions.assertNotNull(nextInterface.addresses());
      Assertions.assertNotNull(nextInterface.flags());
      nextInterface.description();
      Assertions.assertNotNull(nextInterface.toString());
      Address address = nextInterface.addresses();
      Iterator<Address> addressIterator = address.iterator();
      while (addressIterator.hasNext()) {
        Address nextAddress = addressIterator.next();
        nextAddress.address();
        nextAddress.netmask();
        nextAddress.broadcast();
        nextAddress.destination();
        Assertions.assertNotNull(address.toString());
      }
    }
  }

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
            Assertions.assertNotNull(buffer);
            Assertions.assertNotNull(buffer.buffer());
            Assertions.assertNotNull(header);
            Assertions.assertNotEquals(header.captureLength(), 0);
            Assertions.assertNotEquals(header.length(), 0);
            Assertions.assertNotNull(header.timestamp());
            Assertions.assertNotEquals(header.timestamp().microSecond(), 0);
            Assertions.assertNotEquals(header.timestamp().second(), 0L);
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
            Assertions.assertNotNull(buffer.buffer());
            Assertions.assertNotNull(header);
            Assertions.assertNotNull(buffer);
            Assertions.assertNotEquals(header.captureLength(), 0);
            Assertions.assertNotEquals(header.length(), 0);
            Assertions.assertNotNull(header.timestamp());
            Assertions.assertNotEquals(header.timestamp().microSecond(), 0);
            Assertions.assertNotEquals(header.timestamp().second(), 0L);
            try {
              Status status = pcap.status();
              Assertions.assertNotNull(status);
              Assertions.assertTrue(status.dropped() >= 0);
              Assertions.assertTrue(status.droppedByInterface() >= 0);
              Assertions.assertTrue(status.received() >= 0);
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
            Assertions.assertNotNull(buffer);
            Assertions.assertNotNull(buffer.buffer());
            Assertions.assertNotNull(header);
            Assertions.assertNotEquals(header.captureLength(), 0);
            Assertions.assertNotEquals(header.length(), 0);
            Assertions.assertNotNull(header.timestamp());
            Assertions.assertNotEquals(header.timestamp().microSecond(), 0);
            Assertions.assertNotEquals(header.timestamp().second(), 0L);
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
            Assertions.assertNotNull(buffer);
            Assertions.assertNotNull(buffer.buffer());
            Assertions.assertNotNull(header);
            Assertions.assertNotEquals(header.captureLength(), 0);
            Assertions.assertNotEquals(header.length(), 0);
            Assertions.assertNotNull(header.timestamp());
            Assertions.assertNotEquals(header.timestamp().microSecond(), 0);
            Assertions.assertNotEquals(header.timestamp().second(), 0L);
          },
          MAX_PACKET);
    } catch (BreakException e) {
      LOGGER.warn(e);
    }
    pcap.close();
  }

  @Test
  public void liveDispatchTest()
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
      pcap.dispatch(1, (args, header, buffer) -> System.out.println(header), "");
    } catch (BreakException e) {
      LOGGER.warn(e);
    }
    pcap.close();
  }
}
