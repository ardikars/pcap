package pcap.tools.commons;

import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Iterator;
import java.util.Objects;
import java.util.concurrent.TimeoutException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import pcap.api.PcapLive;
import pcap.api.PcapLiveOptions;
import pcap.api.PcapOfflineOptions;
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
import pcap.common.util.Platforms;
import pcap.spi.*;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.WarningException;
import pcap.spi.exception.error.*;

@RequiredArgsConstructor
@Component
public class NetworkDiscovery {

  private static final Logger log = LoggerFactory.getLogger(NetworkDiscovery.class);

  private static final int MAX_TRY = 50;
  private static final int MAX_PKT = 5;

  private final PcapLiveOptions liveOptions;
  private final PcapOfflineOptions offlineOptions;

  public Inet4Address inet4Address(Interface source) throws WarningException {
    Objects.requireNonNull(source);
    Iterator<Address> iterator = source.addresses().iterator();
    while (iterator.hasNext()) {
      Address address = iterator.next();
      if (Objects.nonNull(address.address())
          && address.address() instanceof java.net.Inet4Address
          && Objects.nonNull(address.address().getAddress())
          && Objects.nonNull(address.netmask())
          && address.netmask() instanceof java.net.Inet4Address
          && Objects.nonNull(address.netmask().getAddress())) {
        return Inet4Address.valueOf(address.address().getAddress());
      }
    }
    throw new WarningException("Address not found for " + source.name());
  }

  public MacAddress macAddress(Interface source) throws SocketException, WarningException {
    if (Platforms.isWindows()) {
      throw new WarningException("Doesn't suppported on Windows");
    }
    return NetworkInterface.networkInterfaces()
        .filter(networkInterface -> networkInterface.getName().equals(source.name()))
        .map(
            networkInterface -> {
              try {
                return MacAddress.valueOf(networkInterface.getHardwareAddress());
              } catch (SocketException e) {
                return MacAddress.BROADCAST;
              }
            })
        .filter(macAddress -> !macAddress.isBroadcast())
        .findFirst()
        .orElseGet(() -> MacAddress.BROADCAST);
  }

  public MacAddress macAddress(Interface source, Inet4Address target)
      throws ErrorException, InterfaceNotSupportTimestampTypeException,
          RadioFrequencyModeNotSupportedException, ActivatedException, PermissionDeniedException,
          NoSuchDeviceException, PromiscuousModePermissionDeniedException, InterfaceNotUpException,
          TimestampPrecisionNotSupportedException, SocketException, BreakException {
    MacAddress sorceMacAddress = macAddress(source);
    Inet4Address sourceProtocolAddress = inet4Address(source);
    Arp arp =
        new Arp.Builder()
            .hardwareType(DataLinkLayer.EN10MB)
            .hardwareAddressLength(MacAddress.MAC_ADDRESS_LENGTH)
            .protocolType(NetworkLayer.IPV4)
            .protocolAddressLength(Inet4Address.IPV4_ADDRESS_LENGTH)
            .operationCode(Arp.OperationCode.ARP_REQUEST)
            .senderHardwareAddress(sorceMacAddress)
            .senderProtocolAddress(sourceProtocolAddress)
            .targetProtocolAddress(target)
            .targetHardwareAddress(MacAddress.ZERO)
            .build();
    Ethernet ethernet =
        new Ethernet.Builder()
            .destinationMacAddress(MacAddress.BROADCAST)
            .sourceMacAddress(sorceMacAddress)
            .ethernetType(NetworkLayer.ARP)
            .payloadBuffer(arp.header().buffer())
            .build();

    Pcap pcap = Pcaps.live(new PcapLive(source, liveOptions));
    pcap.setFilter("arp", true);

    Memory memory = Memories.assemble(ethernet.header().buffer(), ethernet.payloadBuffer());

    PacketHeader packetHeader = pcap.allocate(PacketHeader.class);
    PacketBuffer packetBuffer = pcap.allocate(PacketBuffer.class);

    MacAddress macAddress = null;

    loop:
    for (int i = 0; i < MAX_TRY; i++) {
      try {
        pcap.send(memory.nioBuffer(), memory.capacity());
        pcap.nextEx(packetBuffer, packetHeader);
        Memory buffer = Memories.wrap(packetBuffer.buffer());
        buffer.setIndex(0, buffer.capacity());
        Ethernet ethernetResponse = Ethernet.newPacket(buffer);
        Arp arpResponse = ethernetResponse.payload().getFirst(Arp.class);
        if (arpResponse != null
            && arpResponse
                .header()
                .senderProtocolAddress()
                .equals(arp.header().targetProtocolAddress())) {
          if (arpResponse
              .header()
              .senderHardwareAddress()
              .equals(ethernetResponse.header().sourceMacAddress())) {
            macAddress = arpResponse.header().senderHardwareAddress();
            break loop;
          }
        }
        Thread.sleep(1000);
      } catch (TimeoutException e) {
        log.warn(e);
      } catch (InterruptedException e) {
        e.printStackTrace();
      }
    }

    pcap.close();
    if (Objects.isNull(macAddress)) {
      throw new WarningException("Mac address doesn't found.");
    }
    return macAddress;
  }
}
