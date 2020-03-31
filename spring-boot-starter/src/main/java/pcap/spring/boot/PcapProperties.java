package pcap.spring.boot;

import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.context.properties.ConfigurationProperties;
import pcap.api.Pcaps;
import pcap.codec.Packet;
import pcap.spi.Pcap;

@ConditionalOnClass({Pcap.class, Pcaps.class, Packet.class})
@ConfigurationProperties(prefix = "spring.pcap")
public class PcapProperties {

  private boolean unsafe;
}
