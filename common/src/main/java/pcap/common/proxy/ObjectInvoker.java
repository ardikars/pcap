package pcap.common.proxy;

import pcap.common.annotation.Inclubating;

import java.lang.reflect.Method;

@Inclubating
public interface ObjectInvoker {

  Object invoke(Object proxy, Method method, Object... args) throws Throwable;
}
