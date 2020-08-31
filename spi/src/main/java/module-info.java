module pcap.spi {
  exports pcap.spi;
  exports pcap.spi.exception;
  exports pcap.spi.exception.warn;
  exports pcap.spi.exception.error;

  uses pcap.spi.Service;

  provides pcap.spi.Service with
      pcap.spi.Service.NoService;
}
