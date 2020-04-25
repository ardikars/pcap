/** This code is licenced under the GPL version 2. */
package pcap.spring.boot.starter;

import java.util.concurrent.atomic.AtomicInteger;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import pcap.api.PcapLive;
import pcap.api.PcapLiveOptions;
import pcap.api.PcapOfflineOptions;
import pcap.api.Pcaps;
import pcap.api.handler.EventLoopHandler;
import pcap.common.logging.Logger;
import pcap.common.logging.LoggerFactory;
import pcap.common.net.MacAddress;
import pcap.spi.Interface;
import pcap.spi.Pcap;
import pcap.spring.boot.autoconfigure.annotation.EnablePcapPacket;
import pcap.spring.boot.autoconfigure.handler.PcapPacketHandler;

@RequiredArgsConstructor
@SpringBootApplication
@EnablePcapPacket
public class PcapApplication implements CommandLineRunner {

  private static Logger log = LoggerFactory.getLogger(PcapApplication.class);

  private final PcapLiveOptions pcapLiveOptions;
  private final PcapOfflineOptions pcapOfflineOptions;
  private final Interface defaultInterface;
  private final MacAddress defaultMacAddress;

  public static void main(String[] args) {
    SpringApplication.run(PcapApplication.class, args);
  }

  @Override
  public void run(String... args) throws Exception {
    log.info("Pcap live properties     : {}", pcapLiveOptions);
    log.info("Pcap offline properties  : {}", pcapOfflineOptions);
    log.info("Pcap default interface   : {}", defaultInterface.name());
    log.info("Pcap default MAC address : {}", defaultMacAddress);
    log.info("Live capture...");
    AtomicInteger counter = new AtomicInteger();
    Pcap pcap = Pcaps.live(new PcapLive(defaultInterface));
    pcap.loop(
        10,
        (EventLoopPcapPacketHandler<AtomicInteger>)
            (count, header, packet) -> {
              log.info("Packet number {}", count.incrementAndGet());
              log.info("Packet header {}", header);
              log.info("Packet buffer: ");
              packet.forEach(p -> log.info(p.toString()));
            },
        counter);
    pcap.close();
  }

  interface EventLoopPcapPacketHandler<T> extends PcapPacketHandler<T>, EventLoopHandler<T> {}
}
