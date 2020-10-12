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
    Interface source = loopbackInterface(service);
    try (Pcap live = service.live(source, new DefaultLiveOptions().proxy(MyIface.class))) {
      live.setNonBlock(true);
      live.dispatch(
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

  public static Interface loopbackInterface(Service service) throws ErrorException {
    Iterator<Interface> iterator = service.interfaces().iterator();
    if (iterator != null) {
      while (iterator.hasNext()) {
        Interface source = iterator.next();
        if (source.name().equals("lo")) {
          return source;
        }
      }
    }
    throw new ErrorException("Loopback interface is not found.");
  }
}
