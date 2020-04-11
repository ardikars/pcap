/** This code is licenced under the GPL version 2. */
package pcap.api;

import pcap.common.util.Strings;
import pcap.spi.Timestamp;

public class PcapLiveOptions {

  private int snapshotLength; // not zero and not minus
  private boolean promiscuous;
  private boolean rfmon;
  private int timeout; // not zero and not minus
  private boolean immediate;
  private int bufferSize; // not zero and not minus
  private Timestamp.Type timestampType; // nullable
  private Timestamp.Precision timestampPrecision; // not null

  public PcapLiveOptions() {
    this(
        Integer.valueOf(System.getProperty("pcap.snapshotLength", "65535")),
        Boolean.valueOf(System.getProperty("pcap.promiscuous", "true")),
        Boolean.valueOf(System.getProperty("pcap.rfmon", "false")),
        Integer.valueOf(System.getProperty("pcap.timeout", "2000")),
        System.getProperty("pcap.timestampType", null) == null
            ? null
            : Timestamp.Type.valueOf(System.getProperty("pcap.timestampType")),
        Boolean.valueOf(System.getProperty("pcap.immediate", "true")),
        Integer.valueOf(System.getProperty("pcap.bufferSize", "0")),
        System.getProperty("pcap.timestampPrecision", "MICRO").equalsIgnoreCase("MICRO")
            ? Timestamp.Precision.MICRO
            : Timestamp.Precision.NANO);
  }

  private PcapLiveOptions(
      int snapshotLength,
      boolean promiscuous,
      boolean rfmon,
      int timeout,
      Timestamp.Type timestampType,
      boolean immediate,
      int bufferSize,
      Timestamp.Precision timestampPrecision) {
    this.snapshotLength = snapshotLength;
    this.promiscuous = promiscuous;
    this.rfmon = rfmon;
    this.timeout = timeout;
    this.timestampType = timestampType;
    this.immediate = immediate;
    this.bufferSize = bufferSize;
    this.timestampPrecision = timestampPrecision;
  }

  public PcapLiveOptions snapshotLength(int snapshotLength) {
    this.snapshotLength = snapshotLength;
    return this;
  }

  public PcapLiveOptions promiscuous(boolean promiscuous) {
    this.promiscuous = promiscuous;
    return this;
  }

  public PcapLiveOptions rfmon(boolean rfmon) {
    this.rfmon = rfmon;
    return this;
  }

  public PcapLiveOptions timeout(int timeout) {
    this.timeout = timeout;
    return this;
  }

  public PcapLiveOptions timestampType(Timestamp.Type timestampType) {
    this.timestampType = timestampType;
    return this;
  }

  public PcapLiveOptions immediate(boolean immediate) {
    this.immediate = immediate;
    return this;
  }

  public PcapLiveOptions bufferSize(int bufferSize) {
    this.bufferSize = bufferSize;
    return this;
  }

  public PcapLiveOptions timestampPrecision(Timestamp.Precision timestampPrecision) {
    this.timestampPrecision = timestampPrecision;
    return this;
  }

  public int snapshotLength() {
    return snapshotLength;
  }

  public boolean isPromiscuous() {
    return promiscuous;
  }

  public boolean isRfmon() {
    return rfmon;
  }

  public int timeout() {
    return timeout;
  }

  public Timestamp.Type timestampType() {
    return timestampType;
  }

  public boolean isImmediate() {
    return immediate;
  }

  public int bufferSize() {
    return bufferSize;
  }

  public Timestamp.Precision timestampPrecision() {
    return timestampPrecision;
  }

  @Override
  public String toString() {
    return Strings.toStringBuilder(this)
        .add("snapshotLength", snapshotLength)
        .add("promiscuous", promiscuous)
        .add("rfmon", rfmon)
        .add("timeout", timeout)
        .add("immediate", immediate)
        .add("bufferSize", bufferSize)
        .add("timestampType", timestampType)
        .add("timestampPrecision", timestampPrecision)
        .toString();
  }
}
