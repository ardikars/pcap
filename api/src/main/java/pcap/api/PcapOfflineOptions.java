/** This code is licenced under the GPL version 2. */
package pcap.api;

import pcap.common.annotation.Inclubating;
import pcap.spi.Timestamp;

@Inclubating
public class PcapOfflineOptions {

  private Timestamp.Precision timestampPrecision; // nullable

  public PcapOfflineOptions() {
    this(null);
  }

  public PcapOfflineOptions(Timestamp.Precision timestampPrecision) {
    this.timestampPrecision = timestampPrecision;
  }

  public PcapOfflineOptions timestampPrecision(Timestamp.Precision timestampPrecision) {
    this.timestampPrecision = timestampPrecision;
    return this;
  }

  public Timestamp.Precision timestampPrecision() {
    return timestampPrecision;
  }
}
