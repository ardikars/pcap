/** This code is licenced under the GPL version 2. */
package pcap.spring.boot.starter;

import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicInteger;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import pcap.api.PcapLive;
import pcap.api.PcapLiveOptions;
import pcap.api.PcapOfflineOptions;
import pcap.api.Pcaps;
import pcap.codec.Packet;
import pcap.codec.ethernet.Ethernet;
import pcap.common.memory.Memories;
import pcap.common.memory.Memory;
import pcap.common.net.MacAddress;
import pcap.spi.*;
import pcap.spring.boot.autoconfigure.annotation.EnablePcapPacket;

@Slf4j
@RequiredArgsConstructor
@SpringBootApplication
@EnablePcapPacket
public class PcapApplication implements CommandLineRunner {

  private final PcapLiveOptions pcapLiveOptions;
  private final PcapOfflineOptions pcapOfflineOptions;
  private final Interface defaultInterface;
  private final MacAddress defaultMacAddress;

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
        (count, header, buffer) -> {
          log.info("Packet number {}", count.incrementAndGet());
          log.info("Packet header {}", header);
          log.info("Packet buffer {}", buffer);
          ByteBuffer byteBuffer = buffer.buffer();
          Memory memory = Memories.wrap(byteBuffer);
          memory.writerIndex(memory.capacity());
          Packet packet = Ethernet.newPacket(memory);
          packet.forEach(System.out::println);
        },
        counter);
    pcap.close();
  }

  public static void main(String[] args) {
    SpringApplication.run(PcapApplication.class, args);
  }
}
