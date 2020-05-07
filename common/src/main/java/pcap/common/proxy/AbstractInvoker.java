/** This code is licenced under the GPL version 2. */
package pcap.common.proxy;

import java.lang.reflect.Method;
import pcap.common.annotation.Inclubating;
import pcap.common.util.Objects;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public abstract class AbstractInvoker implements ObjectInvoker {

  @Override
  public Object invoke(Object proxy, Method method, Object... args) throws Throwable {
    if (Objects.isHashCode(method)) {
      return Integer.valueOf(System.identityHashCode(proxy));
    }

    if (Objects.isEqualsMethod(method)) {
      return Boolean.valueOf(proxy == args[0]);
    }

    if (Objects.isToStringsMethod(method)) {
      return this.toString();
    }

    return invokeImpl(proxy, method, args);
  }

  public abstract Object invokeImpl(Object proxy, Method method, Object[] args) throws Throwable;
}
