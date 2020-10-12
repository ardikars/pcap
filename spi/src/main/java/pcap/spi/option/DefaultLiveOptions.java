package pcap.spi.option;

import pcap.spi.Pcap;
import pcap.spi.Service;
import pcap.spi.Timestamp;
import pcap.spi.annotation.Incubating;

public class DefaultLiveOptions implements Service.LiveOptions {

  private int snapshotLength;
  private boolean promiscuous;
  private boolean rfmon;
  private int timeout;
  private Timestamp.Type timestampType;
  private boolean immediate;
  private int bufferSize;
  private Timestamp.Precision timestampPrecision;
  private Class<? extends Pcap> proxy;

  public DefaultLiveOptions() {
    this.snapshotLength = 0xFFFF;
    this.promiscuous = true;
    this.rfmon = false;
    this.timeout = 2000;
    this.timestampType = Timestamp.Type.HOST;
    this.immediate = true;
    this.bufferSize = 0;
    this.timestampPrecision = Timestamp.Precision.MICRO;
  }

  @Override
  public int snapshotLength() {
    return snapshotLength;
  }

  @Override
  public Service.LiveOptions snapshotLength(int snapshotLength) {
    this.snapshotLength = snapshotLength;
    return this;
  }

  @Override
  public boolean isPromiscuous() {
    return promiscuous;
  }

  @Override
  public Service.LiveOptions promiscuous(boolean promiscuous) {
    this.promiscuous = promiscuous;
    return this;
  }

  @Override
  public boolean isRfmon() {
    return rfmon;
  }

  @Override
  public Service.LiveOptions rfmon(boolean rfmon) {
    this.rfmon = rfmon;
    return this;
  }

  @Override
  public int timeout() {
    return timeout;
  }

  @Override
  public Service.LiveOptions timeout(int timeout) {
    this.timeout = timeout;
    return this;
  }

  @Override
  public Timestamp.Type timestampType() {
    return timestampType;
  }

  @Override
  public Service.LiveOptions timestampType(Timestamp.Type timestampType) {
    this.timestampType = timestampType;
    return this;
  }

  @Override
  public boolean isImmediate() {
    return immediate;
  }

  @Override
  public Service.LiveOptions immediate(boolean immediate) {
    this.immediate = immediate;
    return this;
  }

  @Override
  public int bufferSize() {
    return bufferSize;
  }

  @Override
  public Service.LiveOptions bufferSize(int bufferSize) {
    this.bufferSize = bufferSize;
    return this;
  }

  @Override
  public Timestamp.Precision timestampPrecision() {
    return timestampPrecision;
  }

  @Override
  public Service.LiveOptions timestampPrecision(Timestamp.Precision timestampPrecision) {
    this.timestampPrecision = timestampPrecision;
    return this;
  }

  @Incubating
  public Service.LiveOptions proxy(Class<? extends Pcap> target) {
    this.proxy = target;
    return this;
  }

  @Incubating
  public Class<? extends Pcap> proxy() {
    return proxy;
  }
}
