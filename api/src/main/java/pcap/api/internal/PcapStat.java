/** This code is licenced under the GPL version 2. */
package pcap.api.internal;

import java.foreign.annotations.NativeGetter;
import java.foreign.annotations.NativeStruct;
import java.foreign.memory.Struct;
import pcap.common.annotation.Inclubating;
import pcap.spi.Status;

/**
 * Wrapper for {@code pcap_stat}
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
@Inclubating
@NativeStruct("[u32(ps_recv)u32(ps_drop)u32(ps_ifdrop)](pcap_stat)")
public interface PcapStat extends Struct<PcapStat> {

  @NativeGetter("ps_recv")
  int received();

  @NativeGetter("ps_drop")
  int dropped();

  @NativeGetter("ps_ifdrop")
  int droppedByInterface();

  default Status status() {
    return new Impl(received(), dropped(), droppedByInterface());
  }

  class Impl implements Status {

    private final int received;
    private final int dropped;
    private final int droppedByInterface;

    private Impl(int received, int dropped, int droppedByInterface) {
      this.received = received;
      this.dropped = dropped;
      this.droppedByInterface = droppedByInterface;
    }

    @Override
    public int received() {
      return received;
    }

    @Override
    public int dropped() {
      return dropped;
    }

    @Override
    public int droppedByInterface() {
      return droppedByInterface;
    }
  }
}
