/** This code is licenced under the GPL version 2. */
package pcap.api.internal;

import java.foreign.annotations.NativeGetter;
import java.foreign.annotations.NativeStruct;
import java.foreign.memory.Struct;
import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
@NativeStruct("[i64(tv_sec)i32(tv_usec)x32](timeval)")
public interface Timestamp extends Struct<Timestamp> {

  @NativeGetter("tv_sec")
  long second();

  @NativeGetter("tv_usec")
  int microSecond();

  default pcap.spi.Timestamp timestamp() {
    return new Impl(second(), microSecond());
  }

  class Impl implements pcap.spi.Timestamp {

    private final long second;
    private final int microSecond;

    Impl(long second, int microSecond) {
      this.second = second;
      this.microSecond = microSecond;
    }

    @Override
    public long second() {
      return second;
    }

    @Override
    public int microSecond() {
      return microSecond;
    }
  }
}
