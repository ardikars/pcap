/** This code is licenced under the GPL version 2. */
package pcap.common.net;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
public class HostAndPortTest extends BaseTest {

    private static final String PREFIX = "https://";
    private static final String HOST_NAME = "ardikars.com";
    private static final Inet4Address INET_4_ADDRESS = Inet4Address.LOCALHOST;
    private static final Inet6Address INET_6_ADDRESS = Inet6Address.LOCALHOST;
    private static final int PORT = 8080;


    private static final HostAndPort IPV4_HOST = HostAndPort.builder()
            .hostName(HOST_NAME)
            .port(PORT)
            .address(INET_4_ADDRESS)
            .build();

    private static final HostAndPort IPV6_HOST = HostAndPort.builder()
            .hostName(HOST_NAME)
            .port(PORT)
            .address(INET_6_ADDRESS)
            .build();

    @Test
    public void ipv6HostName() {
        Assertions.assertEquals(HOST_NAME, IPV6_HOST.getHostName());
    }

    @Test
    public void ipv6HostAddress() {
        Assertions.assertEquals(INET_6_ADDRESS, IPV6_HOST.getHostAddress());
    }

    @Test
    public void ipv6Port() {
        Assertions.assertEquals(PORT , IPV6_HOST.getPort());
    }

    @Test
    public void ipv6HostNameAndPort() {
        Assertions.assertEquals(HOST_NAME + ":" + PORT, IPV6_HOST.hostNameWithPort());
    }

    @Test
    public void ipv6HostNameAndPortWithPrefix() {
        Assertions.assertEquals(PREFIX + HOST_NAME + ":" + PORT, IPV6_HOST.hostNameWithPort(PREFIX));
    }

    @Test
    public void ipv6AddressAndPort() {
        Assertions.assertEquals(INET_6_ADDRESS.toString() + ":" + PORT, IPV6_HOST.hostAddressWithPort());
    }

    @Test
    public void ipv6AddressAndPortWithPrefix() {
        Assertions.assertEquals(PREFIX + INET_6_ADDRESS.toString() + ":" + PORT, IPV6_HOST.hostAddressWithPort(PREFIX));
    }

    @Test
    public void ipv4HostName() {
        Assertions.assertEquals(HOST_NAME, IPV4_HOST.getHostName());
    }

    @Test
    public void ipv4HostAddress() {
        Assertions.assertEquals(INET_4_ADDRESS, IPV4_HOST.getHostAddress());
    }

    @Test
    public void ipv4Port() {
        Assertions.assertEquals(PORT , IPV4_HOST.getPort());
    }

    @Test
    public void ipv4HostNameAndPort() {
        Assertions.assertEquals(HOST_NAME + ":" + PORT, IPV4_HOST.hostNameWithPort());
    }

    @Test
    public void ipv4HostNameAndPortWithPrefix() {
        Assertions.assertEquals(PREFIX + HOST_NAME + ":" + PORT, IPV4_HOST.hostNameWithPort(PREFIX));
    }

    @Test
    public void ipv4AddressAndPort() {
        Assertions.assertEquals(INET_4_ADDRESS.toString() + ":" + PORT, IPV4_HOST.hostAddressWithPort());
    }

    @Test
    public void ipv4AddressAndPortWithPrefix() {
        Assertions.assertEquals(PREFIX + INET_4_ADDRESS.toString() + ":" + PORT, IPV4_HOST.hostAddressWithPort(PREFIX));
    }

}
