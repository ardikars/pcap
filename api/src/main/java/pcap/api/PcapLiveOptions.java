package pcap.api;

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
        Integer.valueOf(System.getProperty("pcap.bufferSize", "65535")),
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
}
