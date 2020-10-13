package pcap.jdk7.internal;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.jdk7.BaseTest;
import pcap.jdk7.MyIface;
import pcap.spi.*;
import pcap.spi.annotation.Async;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.*;
import pcap.spi.option.DefaultLiveOptions;

@RunWith(JUnitPlatform.class)
public class PcapLiveWithProxyTest extends BaseTest {

  @Test
  public void live()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException, BreakException {
    Service service = Service.Creator.create("PcapService");
    try (Pcap pcap =
        service.live(loopbackInterface(service), new DefaultLiveOptions().proxy(MyIface.class))) {
      try {
        pcap.dispatch(
            1,
            new PacketHandler<String>() {
              @Override
              public void gotPacket(String args, PacketHeader header, PacketBuffer buffer) {
                Assertions.assertTrue(header.timestamp().second() > 0);
                Assertions.assertTrue(header.timestamp().microSecond() > 0);
                Assertions.assertTrue(header.captureLength() > 0);
                Assertions.assertTrue(header.length() > 0);
                Assertions.assertEquals(header.captureLength(), buffer.capacity());
              }
            },
            "");
      } catch (ReadPacketTimeoutException e) {
        //
      } catch (ErrorException e) {

      }
      PacketHeader header = pcap.allocate(PacketHeader.class);
      PacketBuffer buffer = pcap.allocate(PacketBuffer.class);
      try {
        pcap.nextEx(header, buffer);
      } catch (ReadPacketTimeoutException e) {
        //
      } catch (ErrorException e) {

      }
      pcap.next(header);
    }
  }

  interface MyProxy extends Pcap {

    @Async
    @Override
    <T> void dispatch(int count, PacketHandler<T> handler, T args)
        throws BreakException, ReadPacketTimeoutException, ErrorException;

    @Async(timeout = 1000)
    @Override
    PacketBuffer next(PacketHeader header);

    @Async(timeout = 0)
    @Override
    void nextEx(PacketHeader packetHeader, PacketBuffer packetBuffer)
        throws BreakException, ReadPacketTimeoutException, ErrorException;
  }
}
