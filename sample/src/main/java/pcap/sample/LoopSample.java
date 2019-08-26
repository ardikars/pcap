package pcap.sample;

import pcap.api.Bootstrap;
import pcap.api.Pcap;
import pcap.spi.Dumper;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public class LoopSample {

    public static void main(String[] args) throws Exception {
        Pcap pcap = Bootstrap.bootstrap()
                .open();
        Dumper dumper = pcap.dumpOpenAppend("/tmp/afjsdfsd.pcap");
        pcap.loop(10, (handler, header, buffer) -> {
            handler.dump(header, buffer);
        }, dumper);
        pcap.close();

    }

}
