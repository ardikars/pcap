package pcap.tests;

import pcap.spi.*;
import pcap.spi.annotation.Async;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.TimeoutException;
import pcap.spi.exception.error.*;
import pcap.spi.option.DefaultLiveOptions;

public class Application {

  public static void main(String[] args)
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Service service = Service.Creator.create("PcapService");
    Interface devices = service.interfaces();
    for (Interface device : devices) {
      System.out.println(
          "[*] Device name   : " + device.name() + " (" + device.description() + ")");
    }
    System.out.println();
    System.out.println("[v] Chosen device : " + devices.name());
    try (Pcap live = service.live(devices, new DefaultLiveOptions().proxy(PcapProxy.class))) {
      PacketBuffer packetBuffer = live.allocate(PacketBuffer.class);
      PacketHeader packetHeader = live.allocate(PacketHeader.class);
      live.nextEx(packetHeader, packetBuffer);
      System.out.println("[ PacketHeader:");
      System.out.println("\tTimestamp -> Second        : " + packetHeader.timestamp().second());
      System.out.println(
          "\tTimestamp -> Micro second  : " + packetHeader.timestamp().microSecond());
      System.out.println("\tCapture length             : " + packetHeader.captureLength());
      System.out.println("\tLength                     : " + packetHeader.length());
      System.out.println("]");
      System.out.println();
      System.out.println(packetBuffer.cast(Ethernet.class));
      System.out.println();
      Statistics statistics = live.stats();
      System.out.println("[ Statistics:");
      System.out.println("\tReceived                   : " + statistics.received());
      System.out.println("\tDropped                    : " + statistics.dropped());
      System.out.println("\tDropped by interface       : " + statistics.droppedByInterface());
      System.out.println("]");
    } catch (TimeoutException e) {
      System.err.println(e);
    } catch (BreakException e) {
      System.err.println(e);
    } catch (ErrorException e) {
      System.err.println(e);
    }
  }

  interface PcapProxy extends Pcap {

    @Async(timeout = 5000)
    @Override
    void nextEx(PacketHeader packetHeader, PacketBuffer packetBuffer)
        throws BreakException, ErrorException, TimeoutException;
  }

  public static class Ethernet extends Packet.Abstract {

    private static final int SIZE = 14;
    private static final int MAC_ADDR_SIZE = 6;

    private final int dstOffset;
    private final int srcOffset;
    private final int typeOffset;

    public Ethernet(PacketBuffer buffer) {
      super(buffer);
      this.dstOffset = 0;
      this.srcOffset = MAC_ADDR_SIZE;
      this.typeOffset = srcOffset + MAC_ADDR_SIZE;
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

    public byte[] destination() {
      byte[] address = new byte[MAC_ADDR_SIZE];
      buffer.getBytes(dstOffset, address);
      return address;
    }

    public byte[] source() {
      byte[] address = new byte[MAC_ADDR_SIZE];
      buffer.getBytes(srcOffset, address);
      return address;
    }

    public int type() {
      return buffer.getShortRE(typeOffset);
    }

    @Override
    protected int size() {
      return SIZE;
    }

    @Override
    public String toString() {
      StringBuilder sb = new StringBuilder();
      sb.append("[ Ethernet: \n");
      sb.append("\tDestination : " + toStringMacAddress(destination()) + "\n");
      sb.append("\tSource      : " + toStringMacAddress(source()) + "\n");
      sb.append("\tType        : " + type() + "\n");
      sb.append("]");
      return sb.toString();
    }
  }
}
