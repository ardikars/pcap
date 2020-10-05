package pcap.api.jdk7;

import com.sun.jna.FunctionMapper;
import com.sun.jna.Library;
import com.sun.jna.NativeLibrary;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;
import pcap.spi.Pcap;
import pcap.spi.exception.ErrorException;
import pcap.spi.option.DefaultEventOptions;

class NativeWaitForSingleObject implements NativeEvent {

  private static final Map<String, Object> NATIVE_LOAD_LIBRARY_OPTIONS =
      new HashMap<String, Object>();

  static {
    final Map<String, String> funcMap = new HashMap<String, String>();
    funcMap.put("WaitForSingleObjectEx", "WaitForSingleObjectEx");
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
  long handle;

  public NativeWaitForSingleObject(DefaultPcap pcap) {
    this.pcap = pcap;
  }

  @Override
  public void init() {
    this.handle = NativeMappings.PlatformDependent.INSTANCE.pcap_getevent(pcap.pointer);
  }

  @Override
  public void listen(int count, Pcap.Event event, Pcap.Event.Options options) {
    DefaultEventOptions opts = (DefaultEventOptions) options;
    int inc = count < 0 ? -1 : 1;
    int cnt = count < 0 ? count - 1 : count;
    while (cnt <= count) {
      long rc;
      do {
        rc = Kernel32.INSTANCE.WaitForSingleObjectEx(handle, opts.timeout(), 1);
      } while (rc < 0 && EINTR == com.sun.jna.Native.getLastError());
      cnt += inc;
      if (rc == 0) {
        event.onReady(options, pcap, Pcap.Event.Operation.READ);
      } else if (rc == 0x00000102L) {
        event.onTimeout(pcap, options);
      } else {
        if (rc == 0x00000080L) {
          event.onError(pcap, options, new ErrorException("WAIT_ABANDONED"));
        }
        if (rc == 0x000000C0L) {
          event.onError(pcap, options, new ErrorException("WAIT_IO_COMPLETION"));
        }
        if (rc == 0xFFFFFFFF) {
          event.onError(pcap, options, new ErrorException("WAIT_FAILED"));
        }
      }
    }
  }

  interface Kernel32 extends Library {

    Kernel32 INSTANCE =
        com.sun.jna.Native.load("Kernel32", Kernel32.class, NATIVE_LOAD_LIBRARY_OPTIONS);

    int WaitForSingleObjectEx(long handle, long dwMilliseconds, int bAlertable);
  }
}
