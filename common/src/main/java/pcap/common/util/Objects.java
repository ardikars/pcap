/** This code is licenced under the GPL version 2. */
package pcap.common.util;

import java.lang.reflect.Method;
import pcap.common.annotation.Inclubating;

@Inclubating
public class Objects {

  public static boolean nonNull(Object object) {
    return java.util.Objects.nonNull(object);
  }

  public static boolean isHashCode(Method method) {
    return "hashCode".equals(method.getName())
        && Integer.TYPE.equals(method.getReturnType())
        && method.getParameterTypes().length == 0;
  }

  public static boolean isEqualsMethod(Method method) {
    return "equals".equals(method.getName())
        && Boolean.TYPE.equals(method.getReturnType())
        && method.getParameterTypes().length == 1
        && Object.class.equals(method.getParameterTypes()[0]);
  }

  public static boolean isToStringsMethod(Method method) {
    return "toString".equals(method.getName())
        && String.class.equals(method.getReturnType())
        && method.getParameterTypes().length == 0;
  }
}
