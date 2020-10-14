package pcap.jdk7.internal;

import com.sun.jna.Platform;
import pcap.spi.Pcap;
import pcap.spi.annotation.Incubating;

@Incubating
interface EventService {

  @Incubating
  <T extends Pcap> T open(Pcap pcap, Class<T> target);

  void close();

  class Creator {

    private Creator() {}

    public static EventService create() {
      return newInstance(Platform.isWindows());
    }

    static EventService newInstance(boolean isWindows) {
      if (isWindows) {
        return new DefaultWaitForSingleObjectEventService();
      } else {
        return new DefaultPollEventService();
      }
    }
  }
}
