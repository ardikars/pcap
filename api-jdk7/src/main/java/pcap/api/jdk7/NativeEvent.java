package pcap.api.jdk7;

import pcap.spi.Pcap;

interface NativeEvent {

  int EINTR = 4;

  void init();

  void listen(int count, Pcap.Event listener, Pcap.Event.Options option);
}
