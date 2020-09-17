package pcap.api.jdk7;

import com.sun.jna.ptr.PointerByReference;
import java.util.concurrent.TimeoutException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.api.BaseTest;
import pcap.spi.Interface;
import pcap.spi.Pcap;
import pcap.spi.Service;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.*;
import pcap.spi.option.DefaultLiveOptions;

@RunWith(JUnitPlatform.class)
public class StructureReferenceTest extends BaseTest {

  private Service service;

  @BeforeEach
  public void setUp() throws ErrorException {
    service = Service.Creator.create("PcapService");
  }

  @Test
  public void newInstance()
      throws ErrorException, TimeoutException, BreakException, PermissionDeniedException,
          PromiscuousModePermissionDeniedException, TimestampPrecisionNotSupportedException,
          RadioFrequencyModeNotSupportedException, NoSuchDeviceException, ActivatedException,
          InterfaceNotUpException, InterfaceNotSupportTimestampTypeException {
    Interface lo = loopbackInterface(service);
    DefaultPacketHeader packetHeader = new DefaultPacketHeader();
    DefaultPacketBuffer packetBuffer = new DefaultPacketBuffer();
    try (Pcap live = service.live(lo, new DefaultLiveOptions())) {
      for (int i = 0; i < 2; i++) {
        live.nextEx(packetHeader, packetBuffer);
      }
    }
    DefaultPacketBuffer newDefaultPacketBuffer = new DefaultPacketBuffer();
    newDefaultPacketBuffer.useMemoryFromReferece(new PointerByReference());
  }
}
