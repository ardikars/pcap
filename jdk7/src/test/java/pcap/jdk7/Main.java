package pcap.jdk7;

import java.util.Iterator;
import pcap.spi.*;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.*;
import pcap.spi.option.DefaultLiveOptions;

public class Main {

  public static void main(String[] args)
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException, BreakException {
    Service service = Service.Creator.create("PcapService");
    Iterator<Interface> iterator = service.interfaces().iterator();
    Interface source = null;
    while (iterator.hasNext()) {
      source = iterator.next();
      if (source.name().contains("Loopback")) {
        break;
      } else {
        source = source.next();
      }
    }
    try (Pcap live = service.live(source, new DefaultLiveOptions())) {
      EventService eventService =
          EventService.Creator.create("PcapWaitForSingleObjectEventService");
      MyIface myIface = eventService.open(live, MyIface.class);
      myIface.dispatch(
          2,
          new PacketHandler<String>() {
            @Override
            public void gotPacket(String args, PacketHeader header, PacketBuffer buffer) {
              System.out.println(header);
            }
          },
          "");
    }
  }
}
