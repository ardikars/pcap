package pcap.jdk7.internal;

import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Platform;
import com.sun.jna.Pointer;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import pcap.spi.*;
import pcap.spi.annotation.Async;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.*;
import pcap.spi.exception.warn.ReadPacketTimeoutException;
import pcap.spi.option.DefaultLiveOptions;

// @RunWith(JUnitPlatform.class)
public class DefaultPollEventServiceTest extends BaseTest {

  private Service service;
  private DefaultPollEventService eventService;

  @BeforeEach
  void setUp() throws ErrorException {
    this.service = Service.Creator.create("PcapService");
    this.eventService = new DefaultPollEventService();
  }

  @Test
  void open()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    if (!Platform.isWindows()) {
      Interface lo = loopbackInterface(service);
      try (Pcap live = service.live(lo, new DefaultLiveOptions())) {
        live.setNonBlock(true);
        if (!Platform.isWindows()) {
          MyProxy myProxy = eventService.open(live, MyProxy.class);
          Assertions.assertNotNull(myProxy);

          try {
            myProxy.dispatch(
                1,
                new PacketHandler<String>() {
                  @Override
                  public void gotPacket(String args, PacketHeader header, PacketBuffer buffer) {
                    // ok
                  }
                },
                "");
          } catch (BreakException e) {
            //
          } catch (ReadPacketTimeoutException e) {
            //
          }
          PacketHeader header = myProxy.allocate(PacketHeader.class);
          PacketBuffer buffer = myProxy.allocate(PacketBuffer.class);
          try {
            myProxy.nextEx(header, buffer);
          } catch (BreakException e) {
            //
          } catch (ReadPacketTimeoutException e) {
            //
          } catch (ErrorException e) {
            //
          }
          buffer = myProxy.next(header);
        }
      }
    }
  }

  @Test
  void normalizeREvents() {
    Pointer pfds = new Memory(8);
    pfds.setShort(6, (short) 1);
    Assertions.assertEquals(0, DefaultPollEventService.normalizeREvents(1, pfds));
    pfds.setShort(6, (short) 4);
    Assertions.assertEquals(-1, DefaultPollEventService.normalizeREvents(1, pfds));
    Assertions.assertEquals(-1, DefaultPollEventService.normalizeREvents(-1, pfds));
    Assertions.assertEquals(1, DefaultPollEventService.normalizeREvents(0, pfds));
    Native.free(Pointer.nativeValue(pfds));
  }

  @Test
  void normalizeTimeout() {
    DefaultTimestamp timestamp = new DefaultTimestamp();
    timestamp.tv_usec.setValue(1000L);
    timestamp.write();
    Assertions.assertEquals(1, DefaultPollEventService.normalizeTimeout(1, timestamp));
    Assertions.assertEquals(1, DefaultPollEventService.normalizeTimeout(0, timestamp));
    Assertions.assertEquals(1, DefaultPollEventService.normalizeTimeout(-1, timestamp));
  }

  @Test
  void register() {
    try {
      DefaultPollEventService.register(false);
    } catch (UnsatisfiedLinkError e) {
    }
    try {
      DefaultPollEventService.register(true);
    } catch (UnsatisfiedLinkError e) {
    }
  }

  interface MyProxy extends Pcap {

    @Async(timeout = 1000) // wait for 1 secs
    @Override
    void nextEx(PacketHeader packetHeader, PacketBuffer packetBuffer)
        throws BreakException, ErrorException;

    @Async(timeout = 0) // no wait
    @Override
    PacketBuffer next(PacketHeader header);

    @Async(timeout = -1) // wait till ready to perform i/o operation
    @Override
    <T> void dispatch(int count, PacketHandler<T> handler, T args)
        throws BreakException, ErrorException;
  }
}
