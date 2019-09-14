/** This code is licenced under the GPL version 2. */
package pcap.api.internal.exception;

import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class PromiscNotSupported extends RuntimeException {

  public PromiscNotSupported(String message) {
    super(message);
  }
}
