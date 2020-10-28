/** This code is licenced under the GPL version 2. */
package pcap.spi.option;

import pcap.spi.Service;
import pcap.spi.Timestamp;
import pcap.spi.annotation.Version;

/** {@inheritDoc} */
public class DefaultOfflineOptions implements Service.OfflineOptions {

  private Timestamp.Precision timestampPrecision;

  /** {@inheritDoc} */
  @Version(major = 1, minor = 5, patch = 0)
  @Override
  public Timestamp.Precision timestampPrecision() {
    return timestampPrecision;
  }

  /** {@inheritDoc} */
  @Version(major = 1, minor = 5, patch = 0)
  @Override
  public Service.OfflineOptions timestampPrecision(Timestamp.Precision timestampPrecision) {
    this.timestampPrecision = timestampPrecision;
    return this;
  }
}
