/** This code is licenced under the GPL version 2. */
package pcap.api;

import pcap.common.annotation.Inclubating;
import pcap.spi.Interface;
import pcap.spi.Timestamp;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public final class Bootstrap extends AbstractBootstrap {

  private Bootstrap(boolean offline) {
    super(offline);
  }

  public static Bootstrap bootstrap() {
    return bootstrap(false);
  }

  public static Bootstrap bootstrap(boolean offline) {
    return new Bootstrap(offline);
  }

  public Bootstrap snaplen(int snaplen) {
    super.snaplen = snaplen;
    return this;
  }

  public Bootstrap promiscuous(boolean promiscuous) {
    super.promiscuous = promiscuous;
    return this;
  }

  public Bootstrap rfmon(boolean rfmon) {
    super.rfmon = rfmon;
    return this;
  }

  public Bootstrap timeout(int timeout) {
    super.timeout = timeout;
    return this;
  }

  public Bootstrap timestampType(Timestamp.Type timestampType) {
    super.timestampType = timestampType;
    return this;
  }

  public Bootstrap immediateMode(boolean immediateMode) {
    super.immediateMode = immediateMode;
    return this;
  }

  public Bootstrap bufferSize(int bufferSize) {
    super.bufferSize = bufferSize;
    return this;
  }

  public Bootstrap timestampPrecision(Timestamp.Precision timestampPrecision) {
    super.timestampPrecision = timestampPrecision;
    return this;
  }

  public Bootstrap source(Interface source) {
    super.source = source;
    return this;
  }

  public Bootstrap file(String file) {
    super.file = file;
    return this;
  }

  @Override
  public Pcap open() throws Exception {
    try {
      return super.openHandle();
    } catch (Exception e) {
      LOGGER.debug(e);
      throw e;
    }
  }
}
