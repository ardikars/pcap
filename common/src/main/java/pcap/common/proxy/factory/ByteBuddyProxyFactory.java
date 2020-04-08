/** This code is licenced under the GPL version 2. */
package pcap.common.proxy.factory;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.loading.ClassLoadingStrategy;
import net.bytebuddy.implementation.InvocationHandlerAdapter;
import net.bytebuddy.matcher.ElementMatchers;
import pcap.common.annotation.Inclubating;
import pcap.common.logging.Logger;
import pcap.common.logging.LoggerFactory;
import pcap.common.proxy.ObjectInvoker;
import pcap.common.proxy.ProxyFactory;
import pcap.common.util.Objects;

@Inclubating
public class ByteBuddyProxyFactory extends ProxyFactory {

  private static final Logger LOGGER = LoggerFactory.getLogger(ByteBuddyProxyFactory.class);

  @Override
  public <T> T createInvokerProxy(
      ClassLoader classLoader, ObjectInvoker invoker, Class<?>... proxyClasses) {
    Class<?> proxyType =
        new ByteBuddy()
            .subclass(Object.class)
            .implement(proxyClasses[0])
            .method(ElementMatchers.isDeclaredBy(proxyClasses[0]))
            .intercept(InvocationHandlerAdapter.of(new InvokerInvocationHandler(invoker)))
            .make()
            .load(classLoader, ClassLoadingStrategy.Default.WRAPPER)
            .getLoaded();
    try {
      return (T) proxyType.getDeclaredConstructor().newInstance();
    } catch (InstantiationException e) {
      LOGGER.error(e);
    } catch (IllegalAccessException e) {
      LOGGER.error(e);
    } catch (InvocationTargetException e) {
      LOGGER.error(e);
    } catch (NoSuchMethodException e) {
      LOGGER.error(e);
    }
    return null;
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
