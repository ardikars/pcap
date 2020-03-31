package pcap.spring.boot.autoconfigure;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Iterator;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureOrder;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import pcap.api.Pcaps;
import pcap.api.internal.PcapAddress;
import pcap.codec.Packet;
import pcap.common.net.MacAddress;
import pcap.common.util.Platforms;
import pcap.spi.Address;
import pcap.spi.Interface;
import pcap.spi.Pcap;
import pcap.spi.exception.ErrorException;
import pcap.spring.boot.PcapLiveProperties;
import pcap.spring.boot.PcapOfflineProperties;
import pcap.spring.boot.PcapProperties;

@Configuration("pcapAutoConfiguration")
@ConditionalOnClass({Pcap.class, Pcaps.class, Packet.class})
@AutoConfigureOrder
@EnableConfigurationProperties({
  PcapProperties.class,
  PcapLiveProperties.class,
  PcapOfflineProperties.class
})
public class PcapAutoConfiguration {

  private final PcapProperties pcapProperties;
  private final PcapLiveProperties pcapLiveProperties;
  private final PcapOfflineProperties pcapOfflineProperties;

  public PcapAutoConfiguration(
      PcapProperties pcapProperties,
      PcapLiveProperties pcapLiveProperties,
      PcapOfflineProperties pcapOfflineProperties) {
    this.pcapProperties = pcapProperties;
    this.pcapLiveProperties = pcapLiveProperties;
    this.pcapOfflineProperties = pcapOfflineProperties;
  }

  @Bean("defaultSource")
  public Interface source() {
    try {
      return Pcaps.lookupInterface();
    } catch (ErrorException e) {
      if (!Platforms.isWindows()) {
        if (Platforms.isLinux()) {
          try {
            return Pcaps.lookupInterface("any");
          } catch (ErrorException ex) {
            throw new RuntimeException("No such device found");
          }
        } else {
          try {
            return Pcaps.lookupInterface("lo");
          } catch (ErrorException ex) {
            throw new RuntimeException("No such device found");
          }
        }
      }
      throw new RuntimeException("No such device found");
    }
  }

  @Bean("defaultNetmask")
  public pcap.common.net.InetAddress netmask(@Qualifier("defaultSource") Interface source) {
    Iterator<Interface> interfaceIterator = source.iterator();
    while (interfaceIterator.hasNext()) {
      Iterator<Address> addressIterator = interfaceIterator.next().addresses().iterator();
      while (addressIterator.hasNext()) {
        Address address = addressIterator.next();
        if (address != null && address instanceof PcapAddress) {
          PcapAddress pcapAddress = (PcapAddress) address;
          InetAddress inetAddress = pcapAddress.netmask();
          if (inetAddress != null && inetAddress instanceof Inet4Address) {
            Inet4Address inet4Address = (Inet4Address) inetAddress;
            return pcap.common.net.Inet4Address.valueOf(inet4Address.getAddress());
          }
        }
      }
    }
    return pcap.common.net.Inet4Address.valueOf("255.255.255.0");
  }

  @Bean("defaultMacAddress")
  public MacAddress macAddress(@Qualifier("defaultSource") Interface source) {
    if (!Platforms.isWindows()) {
      try {
        NetworkInterface networkInterface = NetworkInterface.getByName(source.name());
        return MacAddress.valueOf(networkInterface.getHardwareAddress());
      } catch (SocketException e) {
        return MacAddress.BROADCAST;
      }
    }
    return MacAddress.BROADCAST;
  }
}
