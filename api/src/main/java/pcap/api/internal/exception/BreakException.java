/** This code is licenced under the GPL version 2. */
package pcap.api.internal.exception;

import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class BreakException extends Exception {

  public BreakException(String message) {
    super(message);
  }
}
