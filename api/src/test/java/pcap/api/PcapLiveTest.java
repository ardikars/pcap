/** This code is licenced under the GPL version 2. */
package pcap.api;

import java.foreign.NativeTypes;
import java.foreign.memory.Pointer;
import java.nio.ByteBuffer;
import java.util.Iterator;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.api.handler.EventLoopHandler;
import pcap.api.internal.PcapConstant;
import pcap.api.internal.foreign.pcap_mapping;
import pcap.common.logging.Logger;
import pcap.common.logging.LoggerFactory;
import pcap.common.util.Hexs;
import pcap.spi.*;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.*;
import pcap.spi.exception.warn.PromiscuousModeNotSupported;

// @EnabledOnJre(JRE.JAVA_14)
@RunWith(JUnitPlatform.class)
public class PcapLiveTest {

  private static final Logger LOGGER = LoggerFactory.getLogger(PcapLiveTest.class);

  private static final int MAX_PACKET = 10;
  private static final String FILTER = "ip";

  private Pointer<pcap_mapping.pcap> pcapOpen(Interface source) {
    Pointer<Byte> errbuf = PcapConstant.SCOPE.allocate(NativeTypes.INT8, PcapConstant.ERRBUF_SIZE);
    Pointer<pcap_mapping.pcap> pointer =
        PcapConstant.MAPPING.pcap_create(PcapConstant.SCOPE.allocateCString(source.name()), errbuf);
    return pointer;
  }

  private void pcapClose(Pointer<pcap_mapping.pcap> pointer) {
    PcapConstant.MAPPING.pcap_close(pointer);
  }

  @Test
  public void checkSetSnaplenTest() throws ErrorException {
    Interface source = Pcaps.lookupInterfaces();
    Assertions.assertThrows(
        ActivatedException.class, () -> new PcapLive(source).checkSetSnaplen(-1));
  }

  @Test
  public void checkSetPromiscTest() throws ErrorException {
    Interface source = Pcaps.lookupInterfaces();
    Assertions.assertThrows(
        ActivatedException.class,
        () -> new PcapLive(source, new PcapLiveOptions().promiscuous(true)).checkSetPromisc(-1));
    Assertions.assertThrows(
        ActivatedException.class,
        () -> new PcapLive(source, new PcapLiveOptions().promiscuous(false)).checkSetPromisc(-1));
  }

  @Test
  public void canSetRfmonTest() throws ErrorException, ActivatedException, NoSuchDeviceException {
    Interface source = Pcaps.lookupInterfaces();
    Pointer<pcap_mapping.pcap> pointer = pcapOpen(source);
    Assertions.assertThrows(
        ActivatedException.class, () -> new PcapLive(source).canSetRfmon(pointer, -4));
    Assertions.assertThrows(
        NoSuchDeviceException.class, () -> new PcapLive(source).canSetRfmon(pointer, -5));
    Assertions.assertThrows(
        ErrorException.class, () -> new PcapLive(source).canSetRfmon(pointer, -1));
    Assertions.assertThrows(
        ErrorException.class, () -> new PcapLive(source).canSetRfmon(pointer, -6));
    new PcapLive(source).canSetRfmon(pointer, 1);
    pcapClose(pointer);
  }

  @Test
  public void checkSetRfmonTest() throws ErrorException {
    Interface source = Pcaps.lookupInterfaces();
    Assertions.assertThrows(ActivatedException.class, () -> new PcapLive(source).checkSetRfmon(-1));
  }

  @Test
  public void checkSetTimeoutTest() throws ErrorException {
    Interface source = Pcaps.lookupInterfaces();
    Assertions.assertThrows(
        ActivatedException.class, () -> new PcapLive(source).checkSetTimeout(-1));
  }

  @Test
  public void checkSetTimestampTypeTest()
      throws ErrorException, ActivatedException, InterfaceNotSupportTimestampTypeException {
    Interface source = Pcaps.lookupInterfaces();
    Assertions.assertThrows(
        ActivatedException.class,
        () ->
            new PcapLive(source, new PcapLiveOptions().timestampType(Timestamp.Type.HOST))
                .checkSetTimestampType(-4));
    Assertions.assertThrows(
        InterfaceNotSupportTimestampTypeException.class,
        () ->
            new PcapLive(source, new PcapLiveOptions().timestampType(Timestamp.Type.HOST))
                .checkSetTimestampType(-10));
    new PcapLive(source, new PcapLiveOptions().timestampType(Timestamp.Type.HOST))
        .checkSetTimestampType(3);
  }

  @Test
  public void checkSetImmediateModeTest() throws ErrorException {
    Interface source = Pcaps.lookupInterfaces();
    Assertions.assertThrows(
        ActivatedException.class, () -> new PcapLive(source).checkSetImmediateMode(-1));
  }

  @Test
  public void checkSetBufferSizeTest() throws ErrorException {
    Interface source = Pcaps.lookupInterfaces();
    Assertions.assertThrows(
        ActivatedException.class,
        () -> new PcapLive(source, new PcapLiveOptions().bufferSize(50000)).checkSetBufferSize(-1));
  }

  @Test
  public void checkSetTimestampPrecisionTest() throws ErrorException {
    Interface source = Pcaps.lookupInterfaces();
    Assertions.assertThrows(
        ActivatedException.class, () -> new PcapLive(source).checkSetTimestampPrecision(-4));
    Assertions.assertThrows(
        TimestampPrecisionNotSupportedException.class,
        () -> new PcapLive(source).checkSetTimestampPrecision(-12));
  }

  @Test
  public void checkActivateTest()
      throws ErrorException, PromiscuousModePermissionDeniedException, PermissionDeniedException,
          RadioFrequencyModeNotSupportedException, ActivatedException, InterfaceNotUpException,
          NoSuchDeviceException {
    Interface source = Pcaps.lookupInterfaces();
    Pointer<pcap_mapping.pcap> pointer = pcapOpen(source);
    Assertions.assertThrows(
        PromiscuousModeNotSupported.class, () -> new PcapLive(source).checkActivate(pointer, 2));
    new PcapLive(source).checkActivate(pointer, 3);
    new PcapLive(source).checkActivate(pointer, 1);
    Assertions.assertThrows(
        ActivatedException.class, () -> new PcapLive(source).checkActivate(pointer, -4));
    Assertions.assertThrows(
        NoSuchDeviceException.class, () -> new PcapLive(source).checkActivate(pointer, -5));
    Assertions.assertThrows(
        PermissionDeniedException.class, () -> new PcapLive(source).checkActivate(pointer, -8));
    Assertions.assertThrows(
        PromiscuousModePermissionDeniedException.class,
        () -> new PcapLive(source).checkActivate(pointer, -11));
    Assertions.assertThrows(
        RadioFrequencyModeNotSupportedException.class,
        () -> new PcapLive(source).checkActivate(pointer, -6));
    Assertions.assertThrows(
        InterfaceNotUpException.class, () -> new PcapLive(source).checkActivate(pointer, -9));
    pcapClose(pointer);
  }

  @Test
  public void checkOpenLive()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Interface source = Pcaps.lookupInterfaces();
    try {
      Pcaps.live(
              new PcapLive(
                  source, new PcapLiveOptions().promiscuous(true).rfmon(true).bufferSize(6000000)))
          .close();
    } catch (RadioFrequencyModeNotSupportedException e) {
      System.out.println(e);
    }
    Pcaps.live(
            new PcapLive(
                source, new PcapLiveOptions().promiscuous(false).rfmon(false).bufferSize(0)))
        .close();
  }

  @Test
  public void netmaskTest() throws ErrorException {
    Interface source = Pcaps.lookupInterfaces();
    Assertions.assertNotEquals(0, new PcapLive(source).netmask(source));
  }

  @Test
  public void iterateInterfaceTest() throws ErrorException {
    Interface aInterface = Pcaps.lookupInterfaces();
    Iterator<Interface> interfaceIterator = aInterface.iterator();
    while (interfaceIterator.hasNext()) {
      Interface nextInterface = interfaceIterator.next();
      Assertions.assertNotNull(nextInterface);
      Assertions.assertNotNull(nextInterface.name());
      Assertions.assertTrue(nextInterface.flags() >= 0);
      nextInterface.description();
      Assertions.assertNotNull(nextInterface.toString());
      Address address = nextInterface.addresses();
      if (address != null) {
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
  public void liveEventLoopTest()
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
          (HexHandler)
              (args, header, buffer) -> {
                Assertions.assertEquals(args, MAX_PACKET);
                Assertions.assertNotNull(buffer);
                Assertions.assertNotNull(buffer);
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
      //
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

  @Test
  public void liveNextExTest()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Interface source = Pcaps.lookupInterface();
    Assertions.assertNotNull(source);
    Pcap pcap = Pcaps.live(new PcapLive(source));
    Assertions.assertNotNull(pcap);
    PacketHeader packetHeader = pcap.allocate(PacketHeader.class);
    PacketBuffer packetBuffer = pcap.allocate(PacketBuffer.class);
    IntStream.range(0, 10)
        .forEach(
            value -> {
              try {
                pcap.nextEx(packetBuffer, packetHeader);
                System.out.println(packetHeader);
              } catch (BreakException e) {
                // ok
              } catch (TimeoutException e) {
                // ok
              } catch (ErrorException e) {
                e.printStackTrace();
              }
            });
    pcap.close();
  }

  @Test
  public void nullCheckTest() throws ErrorException {
    Interface source = Pcaps.lookupInterfaces();
    PcapLive live = new PcapLive(source);
    Pointer<Byte> errbuf = PcapConstant.SCOPE.allocate(NativeTypes.INT8, PcapConstant.ERRBUF_SIZE);
    Pointer<pcap_mapping.pcap> pointer =
        PcapConstant.MAPPING.pcap_create(PcapConstant.SCOPE.allocateCString(source.name()), errbuf);
    live.nullCheck(pointer, errbuf);
    Assertions.assertThrows(IllegalStateException.class, () -> live.nullCheck(null, errbuf));
  }

  @Test
  public void pcapLiveOptions() {
    Assertions.assertNotNull(
        new PcapLiveOptions()
            .bufferSize(65535 * 24)
            .immediate(true)
            .promiscuous(true)
            .rfmon(false)
            .snapshotLength(1500)
            .timeout(2000)
            .timestampPrecision(Timestamp.Precision.MICRO)
            .timestampType(Timestamp.Type.ADAPTER));
    Assertions.assertNotNull(
        new PcapLiveOptions()
            .bufferSize(65535 * 24)
            .immediate(true)
            .promiscuous(true)
            .rfmon(false)
            .snapshotLength(1500)
            .timeout(2000)
            .timestampPrecision(Timestamp.Precision.MICRO)
            .timestampType(Timestamp.Type.ADAPTER_UNSYNCED));
    Assertions.assertNotNull(
        new PcapLiveOptions()
            .bufferSize(65535 * 24)
            .immediate(true)
            .promiscuous(true)
            .rfmon(false)
            .snapshotLength(1500)
            .timeout(2000)
            .timestampPrecision(Timestamp.Precision.MICRO)
            .timestampType(Timestamp.Type.HOST));
    Assertions.assertNotNull(
        new PcapLiveOptions()
            .bufferSize(65535 * 24)
            .immediate(true)
            .promiscuous(true)
            .rfmon(false)
            .snapshotLength(1500)
            .timeout(2000)
            .timestampPrecision(Timestamp.Precision.MICRO)
            .timestampType(Timestamp.Type.HOST_HIPREC));
    Assertions.assertNotNull(
        new PcapLiveOptions()
            .bufferSize(65535 * 24)
            .immediate(true)
            .promiscuous(true)
            .rfmon(false)
            .snapshotLength(1500)
            .timeout(2000)
            .timestampPrecision(Timestamp.Precision.MICRO)
            .timestampType(Timestamp.Type.HOST_LOWPREC));
    Assertions.assertNotNull(
        new PcapLiveOptions()
            .bufferSize(65535 * 24)
            .immediate(true)
            .promiscuous(true)
            .rfmon(false)
            .snapshotLength(1500)
            .timeout(2000)
            .timestampPrecision(Timestamp.Precision.MICRO)
            .timestampType(Timestamp.Type.HOST_LOWPREC)
            .toString());
  }

  /**
   * Decode raw packet into hex string.
   *
   * @param <T> args type.
   * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
   */
  public interface HexHandler<T> extends EventLoopHandler<T> {

    @Override
    default void gotPacket(T args, PacketHeader header, PacketBuffer buffer) {
      ByteBuffer byteBuf = buffer.buffer();
      byte[] bytes = new byte[byteBuf.capacity()];
      byteBuf.get(0, bytes);
      String hex = Hexs.toHexString(bytes, 0, byteBuf.capacity());
      gotPacket(args, header, hex);
    }

    void gotPacket(T args, PacketHeader header, String buffer);
  }
}
