package pcap.tools;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import pcap.spring.boot.autoconfigure.annotation.EnablePcapPacket;

@EnablePcapPacket
@SpringBootApplication
public class PcapToolsApplication {

  public static void main(String[] args) {
    SpringApplication.run(PcapToolsApplication.class, args);
  }
}
