package pcap.spring.boot.autoconfigure;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "spring")
@Data
public class SpringProperties {

  private PcapProperties pcap;
}
