/** This code is licenced under the GPL version 2. */
package pcap.spring.boot.autoconfigure;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "spring")
@Data
public class SpringProperties {

  private PcapProperties pcap;
}
