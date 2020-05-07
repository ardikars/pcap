/** This code is licenced under the GPL version 2. */
package pcap.common.util.model;

import java.util.HashMap;
import java.util.Map;
import pcap.common.util.MultipleObject;
import pcap.common.util.NamedMultipleObject;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
public class IcmpTypeAndCode extends NamedMultipleObject<MultipleObject<Byte>, IcmpTypeAndCode> {

  public static final IcmpTypeAndCode NO_ROUTE_TO_DESTINATION =
      new IcmpTypeAndCode(MultipleObject.of((byte) 1, (byte) 0), "No route to destination");

  public static final IcmpTypeAndCode UNKNOWN =
      new IcmpTypeAndCode(MultipleObject.of((byte) -1, (byte) -1), "UNKNOWN");

  private static final Map<MultipleObject<Byte>, IcmpTypeAndCode> registry = new HashMap<>();

  public IcmpTypeAndCode(MultipleObject<Byte> multiKey, String name) {
    super(multiKey, name);
  }

  public static final IcmpTypeAndCode register(final IcmpTypeAndCode icmpTypeAndCode) {
    registry.put(icmpTypeAndCode.value(), icmpTypeAndCode);
    return icmpTypeAndCode;
  }

  public static final IcmpTypeAndCode valueOf(final MultipleObject<Byte> rawValue) {
    IcmpTypeAndCode icmpTypeAndCode = registry.get(rawValue);
    if (icmpTypeAndCode == null) {
      return UNKNOWN;
    }
    return icmpTypeAndCode;
  }

  static {
    registry.put(NO_ROUTE_TO_DESTINATION.value(), NO_ROUTE_TO_DESTINATION);
  }
}
