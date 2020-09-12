package pcap.spi.option;

import pcap.spi.Service;
import pcap.spi.Timestamp;

public class DefaultOfflineOptions implements Service.OfflineOptions {

  private Timestamp.Precision timestampPrecision;

  @Override
  public Timestamp.Precision timestampPrecision() {
    return timestampPrecision;
  }

  @Override
  public Service.OfflineOptions timestampPrecision(Timestamp.Precision timestampPrecision) {
    this.timestampPrecision = timestampPrecision;
    return this;
  }
}
