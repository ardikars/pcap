module pcap.api {
  requires pcap.spi;
  requires pcap.common;

  exports pcap.api;
  exports pcap.api.internal.foreign to
      java.base;
  exports pcap.api.internal.foreign.mapping to
      java.base;
  exports pcap.api.internal.foreign.struct to
      java.base;

  provides pcap.spi.Service with
      pcap.api.internal.PcapService;
}
