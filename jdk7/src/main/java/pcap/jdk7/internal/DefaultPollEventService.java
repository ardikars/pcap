package pcap.jdk7.internal;

import com.sun.jna.*;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import pcap.spi.Pcap;
import pcap.spi.annotation.Async;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.ReadPacketTimeoutException;

class DefaultPollEventService implements EventService, InvocationHandler {

  private static final int EINTR = 4;

  private static final short POLLIN = 0x1;
  private static final int FD_OFFSET = 0;
  private static final int EVENTS_OFFSET = FD_OFFSET + 4;
  private static final int REVENTS_OFFSET = EVENTS_OFFSET + 2;

  static {
    if (!Platform.isWindows()) {
      com.sun.jna.Native.register(
          DefaultPollEventService.class, NativeLibrary.getInstance(Platform.C_LIBRARY_NAME));
    }
  }

  final DefaultPcap pcap;
  final Pointer pfds;

  public DefaultPollEventService() {
    this.pcap = null;
    this.pfds = null;
  }

  public DefaultPollEventService(DefaultPcap pcap, Pointer pfds) {
    this.pcap = pcap;
    this.pfds = pfds;
  }

  static native int poll(Pointer fds, long nfds, int timeout);

  static native DefaultTimestamp pcap_get_required_select_timeout(Pointer p);

  @Override
  public <T extends Pcap> T open(Pcap pcap, Class<T> target) {
    DefaultPcap defaultPcap = (DefaultPcap) pcap;
    Pointer pfds = new Memory(8);
    pfds.setInt(
        FD_OFFSET,
        NativeMappings.PlatformDependent.INSTANCE.pcap_get_selectable_fd(defaultPcap.pointer));
    pfds.setShort(EVENTS_OFFSET, POLLIN);
    return (T)
        Proxy.newProxyInstance(
            target.getClassLoader(),
            new Class[] {target},
            new DefaultPollEventService(defaultPcap, pfds));
  }

  @Override
  public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
    Method m = pcap.getClass().getDeclaredMethod(method.getName(), method.getParameterTypes());
    String methodName = method.getName();
    if (methodName.equals("dispatch") || methodName.equals("next") || methodName.equals("nextEx")) {
      Async async = method.getAnnotation(Async.class);
      if (async != null) {
        int timeout = async.timeout();
        DefaultTimestamp req = pcap_get_required_select_timeout(pcap.pointer);
        if (timeout <= 0 && req != null) {
          timeout = (int) (req.tv_usec.longValue() / 1000L);
        }
        int rc;
        do {
          rc = poll(pfds, 1, timeout);
        } while (rc < 0 && EINTR == com.sun.jna.Native.getLastError());

        if (rc > 0) {
          int revents = pfds.getShort(REVENTS_OFFSET);
          if ((revents & POLLIN) != 0) {
            return m.invoke(pcap, args);
          }
        } else if (rc < 0) {
          throw new ErrorException("");
        } else {
          throw new ReadPacketTimeoutException("");
        }
      }
    }
    return m.invoke(pcap, args);
  }
}
