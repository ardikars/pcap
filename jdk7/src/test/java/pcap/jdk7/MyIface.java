package pcap.jdk7;

import pcap.spi.PacketHandler;
import pcap.spi.Pcap;
import pcap.spi.annotation.Async;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.BreakException;

public interface MyIface extends Pcap {

  @Async(timeout = 1000)
  @Override
  <T> void dispatch(int count, PacketHandler<T> handler, T args)
      throws BreakException, ErrorException;
}
