package pcap.common.proxy;

import java.lang.reflect.Method;
import pcap.common.annotation.Inclubating;

@Inclubating
public interface ObjectInvoker {

  Object invoke(Object proxy, Method method, Object... args) throws Throwable;
}
