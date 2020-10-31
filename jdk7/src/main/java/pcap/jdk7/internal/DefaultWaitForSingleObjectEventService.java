package pcap.jdk7.internal;

import com.sun.jna.NativeLibrary;
import com.sun.jna.Platform;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import pcap.spi.Pcap;
import pcap.spi.annotation.Async;

class DefaultWaitForSingleObjectEventService extends AbstractEventService
    implements InvocationHandler {

  static {
    register(Platform.isWindows());
  }

  final long handle;

  DefaultWaitForSingleObjectEventService() {
    super(null);
    this.handle = 0;
  }

  private DefaultWaitForSingleObjectEventService(DefaultPcap pcap, long handle) {
    super(pcap);
    this.handle = handle;
  }

  static void register(boolean isWindows) {
    if (isWindows) {
      com.sun.jna.Native.register(
          DefaultWaitForSingleObjectEventService.class, NativeLibrary.getInstance("Kernel32"));
    }
  }

  static native int WaitForSingleObjectEx(long handle, long dwMilliseconds, int bAlertable);

  @Override
  public <T extends Pcap> T open(Pcap pcap, Class<T> target) {
    DefaultPcap defaultPcap = (DefaultPcap) pcap;
    long handle = NativeMappings.PlatformDependent.INSTANCE.pcap_getevent(defaultPcap.pointer);
    return newProxy(target, new DefaultWaitForSingleObjectEventService(defaultPcap, handle));
  }

  @Override
  public Object invoke(Object proxy, Method proxyMethod, Object[] args) throws Throwable {
    Method pcapMethod =
        pcap.getClass().getDeclaredMethod(proxyMethod.getName(), proxyMethod.getParameterTypes());
    Async async = getAsync(proxyMethod);
    if (async == null) {
      return invoke(pcapMethod, args);
    }
    int events;
    do {
      events = WaitForSingleObjectEx(handle, async.timeout(), 1);
    } while (events < 0 && EINTR == com.sun.jna.Native.getLastError());
    return invokeOnReady(events, 0L, 0x00000102L, pcapMethod, args);
  }
}
