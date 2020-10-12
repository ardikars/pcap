package pcap.jdk7.internal;

import com.sun.jna.NativeLibrary;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import pcap.spi.EventService;
import pcap.spi.Pcap;
import pcap.spi.annotation.Async;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.ReadPacketTimeoutException;

public class DefaultWaitForSingleObjectEventService implements EventService, InvocationHandler {

  private static final int EINTR = 4;

  static {
    if (com.sun.jna.Platform.isWindows()) {
      com.sun.jna.Native.register(
          DefaultWaitForSingleObjectEventService.class, NativeLibrary.getInstance("Kernel32"));
    }
  }

  final Pcap pcap;
  final long handle;

  public DefaultWaitForSingleObjectEventService() {
    this.pcap = null;
    this.handle = 0;
  }

  private DefaultWaitForSingleObjectEventService(Pcap pcap, long handle) {
    this.pcap = pcap;
    this.handle = handle;
  }

  static native int WaitForSingleObjectEx(long handle, long dwMilliseconds, int bAlertable);

  @Override
  public String name() {
    return "PcapWaitForSingleObjectEventService";
  }

  @Override
  public <T extends Pcap> T open(Pcap pcap, Class<T> target) {
    DefaultPcap defaultPcap = (DefaultPcap) pcap;
    long handle = NativeMappings.PlatformDependent.INSTANCE.pcap_getevent(defaultPcap.pointer);
    return (T)
        Proxy.newProxyInstance(
            target.getClassLoader(),
            new Class[] {target},
            new DefaultWaitForSingleObjectEventService(defaultPcap, handle));
  }

  @Override
  public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
    Method m = pcap.getClass().getDeclaredMethod(method.getName(), method.getParameterTypes());
    String methodName = method.getName();
    if (methodName.equals("dispatch") || methodName.equals("next") || methodName.equals("nextEx")) {
      Async async = method.getAnnotation(Async.class);
      if (async != null) {
        int events;
        do {
          events = WaitForSingleObjectEx(handle, async.timeout(), 1);
        } while (events < 0 && EINTR == com.sun.jna.Native.getLastError());
        if (events == 0L) {
          return m.invoke(pcap, args);
        } else if (events == 0x00000102L) {
          throw new ReadPacketTimeoutException("");
        } else {
          throw new ErrorException("");
        }
      }
    }
    return m.invoke(pcap, args);
  }
}
