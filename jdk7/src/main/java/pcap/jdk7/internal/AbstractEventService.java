package pcap.jdk7.internal;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import pcap.spi.annotation.Async;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.ReadPacketTimeoutException;

abstract class AbstractEventService implements EventService {

  protected static final int EINTR = 4;

  final DefaultPcap pcap;

  protected AbstractEventService(DefaultPcap pcap) {
    this.pcap = pcap;
  }

  protected Async getAsync(Method method) {
    String methodName = method.getName();
    if (methodName.equals("dispatch") || methodName.equals("next") || methodName.equals("nextEx")) {
      return method.getAnnotation(Async.class);
    }
    return null;
  }

  protected <T> T newProxy(Class<T> target, InvocationHandler handler) {
    return (T) Proxy.newProxyInstance(target.getClassLoader(), new Class[] {target}, handler);
  }

  protected Object invoke(Method method, Object... args) throws ErrorException {
    try {
      if (method.getName().equals("close")) {
        close();
      }
      return method.invoke(pcap, args);
    } catch (IllegalAccessException e) {
      throw new ErrorException(e.getMessage());
    } catch (InvocationTargetException e) {
      throw new ErrorException(e.getMessage());
    }
  }

  protected Object invokeOnReady(long rc, long success, long timeout, Method method, Object... args)
      throws ErrorException {
    if (method.getName().equals("next") && rc != success) {
      return null;
    }
    if (rc != success) {
      if (rc == timeout) {
        throw new ReadPacketTimeoutException("");
      } else {
        throw new ErrorException("");
      }
    }
    return invoke(method, args);
  }
}
