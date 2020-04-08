/** This code is licenced under the GPL version 2. */
package pcap.spring.boot.autoconfigure;

import lombok.Data;
import pcap.spi.Timestamp;

@Data
public class PcapLiveProperties {

  private Integer snapshotLength; // not zero and not minus
  private Boolean promiscuous;
  private Boolean rfmon;
  private Integer timeout; // not zero and not minus
  private Boolean immediate;
  private Integer bufferSize; // not zero and not minus
  private Timestamp.Type timestampType; // nullable
  private Timestamp.Precision timestampPrecision; // not null
}
