/** This code is licenced under the GPL version 2. */
package pcap.common.proxy.factory;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import pcap.common.annotation.Inclubating;
import pcap.common.proxy.ObjectInvoker;
import pcap.common.proxy.ProxyFactory;
import pcap.common.util.Objects;

@Inclubating
public class JdkProxyFactory extends ProxyFactory {

  @Override
  public <T> T createInvokerProxy(
      ClassLoader classLoader, ObjectInvoker invoker, Class<?>... proxyClasses) {
    @SuppressWarnings("unchecked")
    T result =
        (T)
            Proxy.newProxyInstance(
                classLoader, proxyClasses, new InvokerInvocationHandler(invoker));
    return result;
  }

  private abstract static class AbstractInvocationHandler implements InvocationHandler {

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
      if (Objects.isHashCode(method)) {
        return Integer.valueOf(System.identityHashCode(proxy));
      }

      if (Objects.isEqualsMethod(method)) {
        return Boolean.valueOf(proxy == args[0]);
      }

      return invokeImpl(proxy, method, args);
    }

    protected abstract Object invokeImpl(Object proxy, Method method, Object[] args)
        throws Throwable;
  }

  private static class InvokerInvocationHandler extends AbstractInvocationHandler {

    private final ObjectInvoker invoker;

    public InvokerInvocationHandler(ObjectInvoker invoker) {
      this.invoker = invoker;
    }

    @Override
    public Object invokeImpl(Object proxy, Method method, Object[] args) throws Throwable {
      return invoker.invoke(proxy, method, args);
    }
  }
}
