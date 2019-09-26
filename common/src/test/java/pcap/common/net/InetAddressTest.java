/** This code is licenced under the GPL version 2. */
package pcap.common.net;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
public class InetAddressTest extends BaseTest {

    private static final String IPV4_LOCALHOST_ADDRESS = "127.0.0.1";

    private static final String IPV6_LOCALHOST_ADDRESS = "::1";

    @Test
    public void validIpv4() {
        Assertions.assertEquals(true, isValidAddress(IPV4_LOCALHOST_ADDRESS));
    }

    @Test
    public void ipv4() {
        InetAddress address = fromString(IPV4_LOCALHOST_ADDRESS);
        Assertions.assertEquals(true, (address instanceof Inet4Address));
    }

    @Test
    public void validIpv6() {
        Assertions.assertEquals(true, isValidAddress(IPV6_LOCALHOST_ADDRESS));
    }

    @Test
    public void ipv6() {
        InetAddress address = fromString(IPV6_LOCALHOST_ADDRESS);
        Assertions.assertEquals(true, (address instanceof Inet6Address));
    }

    private InetAddress fromString(String address) {
        return InetAddress.valueOf(address);
    }

    private boolean isValidAddress(String address) {
        return InetAddress.isValidAddress(address);
    }

}
