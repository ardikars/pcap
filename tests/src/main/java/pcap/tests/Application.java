package pcap.tests;

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
      byte[] dstBuf = new byte[14];
      packetBuffer.readBytes(dstBuf);
      System.out.println("Destination : " + toStringMacAddress(dstBuf));
      packetBuffer.readBytes(dstBuf);
      System.out.println("Source      : " + toStringMacAddress(dstBuf));
      System.out.println("Type        : " + packetBuffer.readShort());
    }
  }

  private static String toStringMacAddress(byte[] address) {
    final StringBuilder sb = new StringBuilder();
    for (final byte b : address) {
      if (sb.length() > 0) {
        sb.append(':');
      }
      String hex = Integer.toHexString(b & 0xff);
      if (hex.length() == 1) {
        sb.append('0' + hex);
      } else {
        sb.append(hex);
      }
    }
    return sb.toString();
  }
}
