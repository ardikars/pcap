/** This code is licenced under the GPL version 2. */
package pcap.spring.boot.autoconfigure;

import java.net.NetworkInterface;
import java.net.SocketException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureOrder;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import pcap.api.PcapLiveOptions;
import pcap.api.PcapOfflineOptions;
import pcap.api.Pcaps;
import pcap.codec.Packet;
import pcap.common.net.MacAddress;
import pcap.common.util.Objects;
import pcap.common.util.Platforms;
import pcap.spi.Interface;
import pcap.spi.Pcap;
import pcap.spi.exception.ErrorException;

@Configuration("pcapAutoConfiguration")
@ConditionalOnClass({Pcap.class, Pcaps.class, Packet.class})
@AutoConfigureOrder
@EnableConfigurationProperties({SpringProperties.class})
@RequiredArgsConstructor
public class PcapAutoConfiguration {

  private final SpringProperties springProperties;

  @Bean("defaultPcapLiveOptions")
  @ConditionalOnMissingBean(PcapLiveOptions.class)
  public PcapLiveOptions pcapLiveOptions() {
    PcapLiveOptions options = new PcapLiveOptions();
    if (Objects.nonNull(springProperties.getPcap())
        && Objects.nonNull(springProperties.getPcap().getLive())) {
      PcapLiveProperties properties = springProperties.getPcap().getLive();
      if (Objects.nonNull(properties.getSnapshotLength())) {
        options.snapshotLength(properties.getSnapshotLength());
      }
      if (Objects.nonNull(properties.getPromiscuous())) {
        options.promiscuous(properties.getPromiscuous());
      }
      if (Objects.nonNull(properties.getRfmon())) {
        options.rfmon(properties.getRfmon());
      }
      if (Objects.nonNull(properties.getTimeout())) {
        options.timeout(properties.getTimeout());
      }
      if (Objects.nonNull(properties.getImmediate())) {
        options.immediate(properties.getImmediate());
      }
      if (Objects.nonNull(properties.getBufferSize())) {
        options.bufferSize(properties.getBufferSize());
      }
      if (Objects.nonNull(properties.getTimestampType())) {
        options.timestampType(properties.getTimestampType());
      }
      if (Objects.nonNull(properties.getTimestampPrecision())) {
        options.timestampPrecision(properties.getTimestampPrecision());
      }
    }
    return options;
  }

  @Bean("defaultPcapOfflineOptions")
  @ConditionalOnMissingBean(PcapOfflineOptions.class)
  public PcapOfflineOptions pcapOfflineOptions() {
    PcapOfflineOptions options = new PcapOfflineOptions();
    if (Objects.nonNull(springProperties.getPcap())
        && Objects.nonNull(springProperties.getPcap().getOffline())) {
      PcapOfflineProperties properties = springProperties.getPcap().getOffline();
      if (Objects.nonNull(properties.getTimestampPrecision())) {
        options.timestampPrecision(properties.getTimestampPrecision());
      }
    }
    return options;
  }

  @Bean("defaultSource")
  @ConditionalOnMissingBean(Interface.class)
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

  @Bean("defaultMacAddress")
  @ConditionalOnMissingBean(MacAddress.class)
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
