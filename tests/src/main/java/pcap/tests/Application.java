package pcap.tests;

import pcap.spi.Interface;
import pcap.spi.Pcap;
import pcap.spi.Service;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.*;
import pcap.spi.option.DefaultLiveOptions;

public class Application {

  public static void main(String[] args)
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException, BreakException {
    Service service = Service.Creator.create("PcapService");
    Interface devices = service.interfaces();
    for (Interface device : devices) {
      System.out.println(
          "[*] Device name   : " + device.name() + " (" + device.description() + ")");
    }
    System.out.println();
    System.out.println("[v] Chosen device : " + devices.name());
    try (Pcap live = service.live(devices, new DefaultLiveOptions())) {
      live.loop(
          10,
          (args1, header, buffer) -> {
            System.out.println("Header  : " + header);
          },
          "Hello Pcap!");
    }
  }
}
