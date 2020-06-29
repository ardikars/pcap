/** This code is licenced under the GPL version 2. */
package pcap.common.util;

import pcap.common.annotation.Inclubating;

@Inclubating
public final class Objects {

  private Objects() {
    //
  }

  public static boolean nonNull(Object object) {
    return java.util.Objects.nonNull(object);
  }
}
