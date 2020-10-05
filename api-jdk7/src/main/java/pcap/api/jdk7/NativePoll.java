package pcap.api.jdk7;

import com.sun.jna.*;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;
import pcap.spi.Pcap;
import pcap.spi.exception.ErrorException;
import pcap.spi.option.DefaultEventOptions;

class NativePoll implements NativeEvent {

  private static final short POLLIN = 0x1;
  private static final short POLLOUT = 0x4;
  private static final int FD_OFFSET = 0;
  private static final int EVENTS_OFFSET = FD_OFFSET + 4;
  private static final int REVENTS_OFFSET = EVENTS_OFFSET + 2;

  private static final Map<String, Object> NATIVE_LOAD_LIBRARY_OPTIONS =
      new HashMap<String, Object>();

  static {
    final Map<String, String> funcMap = new HashMap<String, String>();
    funcMap.put("poll", "poll");
    NATIVE_LOAD_LIBRARY_OPTIONS.put(
        Library.OPTION_FUNCTION_MAPPER,
        new FunctionMapper() {
          @Override
          public String getFunctionName(NativeLibrary library, Method method) {
            return funcMap.get(method.getName());
          }
        });
  }

  final DefaultPcap pcap;
  final Pointer pfds;

  public NativePoll(DefaultPcap pcap) {
    this.pcap = pcap;
    this.pfds = new Pointer(Native.malloc(8));
  }

  @Override
  public void init() {
    this.pfds.setInt(
        FD_OFFSET, NativeMappings.PlatformDependent.INSTANCE.pcap_get_selectable_fd(pcap.pointer));
    this.pfds.setShort(EVENTS_OFFSET, POLLIN);
  }

  @Override
  public void listen(int count, Pcap.Event event, Pcap.Event.Options options) {
    DefaultEventOptions opts = (DefaultEventOptions) options;
    int inc = count < 0 ? -1 : 1;
    int cnt = count < 0 ? count - 1 : count;
    while (cnt <= count) {
      DefaultTimestamp req =
          NativeMappings.PlatformDependent.INSTANCE.pcap_get_required_select_timeout(pcap.pointer);
      int timeout = opts.timeout();
      if (timeout <= 0 && req != null) {
        timeout = (int) (req.tv_usec.longValue() / 1000L);
      }
      int rc;
      do {
        rc = LibC.INSTANCE.poll(pfds, 1, timeout);
      } while (rc < 0 && EINTR == com.sun.jna.Native.getLastError());
      cnt += inc;
      if (rc < 0) {
        event.onError(pcap, options, new ErrorException(""));
      } else if (rc > 0) {
        int revents = pfds.getShort(REVENTS_OFFSET);
        if ((revents & POLLIN) != 0) {
          event.onReady(options, pcap, Pcap.Event.Operation.READ);
        }
        if ((revents & POLLOUT) != 0) {
          event.onReady(options, pcap, Pcap.Event.Operation.WRITE);
        }
      } else {
        event.onTimeout(pcap, options);
      }
    }
  }

  interface LibC extends Library {

    LibC INSTANCE = com.sun.jna.Native.load("c", LibC.class, NATIVE_LOAD_LIBRARY_OPTIONS);

    int poll(Pointer fds, long nfds, int timeout);
  }
}
