/** This code is licenced under the GPL version 2. */
package pcap.common.proxy;

import pcap.common.annotation.Inclubating;
import pcap.common.proxy.factory.ByteBuddyProxyFactory;
import pcap.common.proxy.factory.JdkProxyFactory;

@Inclubating
public abstract class ProxyFactory {

  private static ProxyFactory DEFAULT_PROXY_FACTORY;

  private static ProxyFactory getDefaultProxyFactory() {
    if (DEFAULT_PROXY_FACTORY == null) {
      DEFAULT_PROXY_FACTORY = newDefaultFactory();
    }
    return DEFAULT_PROXY_FACTORY;
  }

  private static ProxyFactory newDefaultFactory() {
    try {
      Class.forName("net.bytebuddy.ByteBuddy");
      return new ByteBuddyProxyFactory();
    } catch (ClassNotFoundException e) {
      return new JdkProxyFactory();
    }
  }

  public boolean canProxy(Class<?>... proxyClasses) {
    if (proxyClasses == null) {
      throw new RuntimeException("Only support single interface.");
    }
    for (Class<?> proxyClass : proxyClasses) {
      if (!proxyClass.isInterface()) {
        return false;
      }
    }
    return true;
  }

  public <T> T createInvokerProxy(ObjectInvoker invoker, Class<?>... proxyClasses) {
    return createInvokerProxy(
        Thread.currentThread().getContextClassLoader(), invoker, proxyClasses);
  }

  public abstract <T> T createInvokerProxy(
      ClassLoader classLoader, ObjectInvoker invoker, Class<?>... proxyClasses);

  public static ProxyFactory factory() {
    return getDefaultProxyFactory();
  }
}
