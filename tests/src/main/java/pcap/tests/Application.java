package pcap.tests;

import pcap.common.net.MacAddress;
import pcap.spi.*;
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
      PacketBuffer packetBuffer = live.allocate(PacketBuffer.class);
      PacketHeader packetHeader = live.allocate(PacketHeader.class);
      live.nextEx(packetHeader, packetBuffer);
      byte[] dstBuf = new byte[MacAddress.MAC_ADDRESS_LENGTH];
      packetBuffer.readBytes(dstBuf);
      System.out.println("Destination : " + MacAddress.valueOf(dstBuf));
      packetBuffer.readBytes(dstBuf);
      System.out.println("Source      : " + MacAddress.valueOf(dstBuf));
      System.out.println("Type        : " + packetBuffer.readShort());
    }
  }
}
