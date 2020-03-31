package pcap.spring.boot.autoconfigure;

import lombok.Data;
import pcap.spi.Timestamp;

@Data
public class PcapOfflineProperties {

  private Timestamp.Precision timestampPrecision; // nullable
}
