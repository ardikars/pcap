package pcap.spring.boot.autoconfigure;

import lombok.Data;

@Data
public class PcapProperties {

  private Boolean unsafe;
  private PcapLiveProperties live;
  private PcapOfflineProperties offline;
}
