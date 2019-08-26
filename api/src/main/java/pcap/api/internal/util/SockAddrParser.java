/**
 * This code is licenced under the GPL version 2.
 */
package pcap.api.internal.util;

import pcap.api.internal.foreign.pcap_mapping;
import pcap.common.logging.Logger;
import pcap.common.logging.LoggerFactory;

import java.foreign.memory.Pointer;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public class SockAddrParser {

    private static final Logger LOGGER = LoggerFactory.getLogger(SockAddrParser.class);

    private static final SockAddrParser PARSER = new SockAddrParser();

    public static SockAddrParser getInstance() {
        return PARSER;
    }

    public InetAddress parse(Pointer<pcap_mapping.sockaddr> pointer) {
        try {
            if (!pointer.isNull()) {
                pcap_mapping.sockaddr sockaddr = pointer.get();
                if (sockaddr.sa_family$get() == 2) {
                    byte[] data = new byte[4];
                    for (int i = 0; i < data.length; i++) {
                        data[i] = sockaddr.sa_data$get().get(i + 2);
                    }
                        return Inet4Address.getByAddress(data);

                } else if (sockaddr.sa_family$get() == 10) {
                    byte[] data = new byte[16];
                    for (int i = 0; i < data.length; i++) {
                        data[i] = sockaddr.sa_data$get().get(i);
                    }
                    return Inet6Address.getByAddress(data);
                }
            } else {
                LOGGER.warn("pointer (null)");
            }
        } catch (UnknownHostException e) {
            LOGGER.error(e);
        }
        return null;
    }

}
