/** This code is licenced under the GPL version 2. */
package pcap.common.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.common.util.model.IcmpTypeAndCode;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@RunWith(JUnitPlatform.class)
public class NamedMultiKeyTest {

  public static final MultipleObject<Byte> NO_ROUTE_TO_DESTINATION =
      MultipleObject.of((byte) 1, (byte) 0);
  public static final MultipleObject<Byte>
      COMMUNICATION_WITH_DESTINATION_ADMINIS_TRATIVELY_PROHIBITED =
          MultipleObject.of((byte) 1, (byte) 1);
  public static final MultipleObject<Byte> UNKNOWN_CODE = MultipleObject.of((byte) -1, (byte) -1);

  @Test
  public void found() {
    IcmpTypeAndCode icmpTypeAndCode = IcmpTypeAndCode.valueOf(NO_ROUTE_TO_DESTINATION);
    Assertions.assertEquals(
        IcmpTypeAndCode.NO_ROUTE_TO_DESTINATION.value(), icmpTypeAndCode.value());
  }

  @Test
  public void notFound() {
    IcmpTypeAndCode icmpTypeAndCode = IcmpTypeAndCode.valueOf(UNKNOWN_CODE);
    Assertions.assertEquals(IcmpTypeAndCode.UNKNOWN.value(), icmpTypeAndCode.value());
  }

  @Test
  public void registerNewCode() {
    /** Register icmp type and code. */
    IcmpTypeAndCode icmpTypeAndCode =
        new IcmpTypeAndCode(
            COMMUNICATION_WITH_DESTINATION_ADMINIS_TRATIVELY_PROHIBITED,
            "Communication with destination administratively prohibited");
    IcmpTypeAndCode.register(icmpTypeAndCode);

    /** Test */
    IcmpTypeAndCode communicationWithxxx =
        IcmpTypeAndCode.valueOf(COMMUNICATION_WITH_DESTINATION_ADMINIS_TRATIVELY_PROHIBITED);
    Assertions.assertEquals(
        COMMUNICATION_WITH_DESTINATION_ADMINIS_TRATIVELY_PROHIBITED, communicationWithxxx.value());
  }
}
