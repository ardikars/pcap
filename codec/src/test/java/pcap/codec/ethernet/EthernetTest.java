package pcap.codec.ethernet;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.common.net.MacAddress;
import pcap.spi.PacketBuffer;
import pcap.spi.Pcap;
import pcap.spi.Service;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.*;
import pcap.spi.option.DefaultLiveOptions;

@RunWith(JUnitPlatform.class)
public class EthernetTest {

  @Test
  void readWrite()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Service service = Service.Creator.create("PcapService");
    try (final Pcap pcap = service.live(service.interfaces(), new DefaultLiveOptions())) {
      PacketBuffer buffer = pcap.allocate(PacketBuffer.class).capacity(14);
      buffer.setIndex(0, buffer.capacity());
      Ethernet ethernet = buffer.cast(Ethernet.class);
      // write
      ethernet.destination(MacAddress.BROADCAST);
      ethernet.source(MacAddress.DUMMY);
      ethernet.type(0x0806);

      // read
      Assertions.assertEquals(MacAddress.BROADCAST, ethernet.destination());
      Assertions.assertEquals(MacAddress.DUMMY, ethernet.source());
      Assertions.assertEquals(0x0806, ethernet.type());

      // to string
      Assertions.assertNotNull(ethernet.toString());

      // release buffer
      buffer.release();
    }
  }
}
