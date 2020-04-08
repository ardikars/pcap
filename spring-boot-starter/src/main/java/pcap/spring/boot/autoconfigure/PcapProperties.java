/** This code is licenced under the GPL version 2. */
package pcap.spring.boot.autoconfigure;

import lombok.Data;
import pcap.spi.Pcap;

@Data
public class PcapProperties {

  private Boolean unsafe;
  private Boolean checkBounds;
  private Boolean blocking;
  private Pcap.Direction direction;
  private PcapLiveProperties live;
  private PcapOfflineProperties offline;
}
