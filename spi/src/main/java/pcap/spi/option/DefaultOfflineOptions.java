/** This code is licenced under the GPL version 2. */
package pcap.spi.option;

import pcap.spi.Service;
import pcap.spi.Timestamp;

/** {@inheritDoc} */
public class DefaultOfflineOptions implements Service.OfflineOptions {

  private Timestamp.Precision timestampPrecision;

  /** {@inheritDoc} */
  @Override
  public Timestamp.Precision timestampPrecision() {
    return timestampPrecision;
  }

  /** {@inheritDoc} */
  @Override
  public Service.OfflineOptions timestampPrecision(Timestamp.Precision timestampPrecision) {
    this.timestampPrecision = timestampPrecision;
    return this;
  }
}
