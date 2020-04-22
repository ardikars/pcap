/** This code is licenced under the GPL version 2. */
package pcap.spring.boot.autoconfigure;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Configuration;
import pcap.codec.DataLinkLayer;
import pcap.codec.NetworkLayer;
import pcap.codec.TransportLayer;
import pcap.codec.arp.Arp;
import pcap.codec.ethernet.Ethernet;
import pcap.codec.ethernet.Vlan;
import pcap.codec.icmp.Icmp4;
import pcap.codec.icmp.Icmp6;
import pcap.codec.ip.Ip4;
import pcap.codec.ip.Ip6;
import pcap.codec.ip.ip6.*;
import pcap.codec.tcp.Tcp;
import pcap.codec.udp.Udp;
import pcap.common.logging.Logger;
import pcap.common.logging.LoggerFactory;

@Configuration("pcapPacketAutoConfiguration")
public class PcapPacketAutoConfiguration implements InitializingBean, ApplicationContextAware {

  private static final Logger LOGGER = LoggerFactory.getLogger(PcapPacketAutoConfiguration.class);

  private ApplicationContext applicationContext;

  @Override
  public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
    this.applicationContext = applicationContext;
  }

  @Override
  public void afterPropertiesSet() {
    if (LOGGER.isDebugEnabled()) {
      LOGGER.debug("Enable pcap packet.");
    }
    DataLinkLayer.register(DataLinkLayer.EN10MB, new Ethernet.Builder());
    NetworkLayer.register(NetworkLayer.ARP, new Arp.Builder());
    NetworkLayer.register(NetworkLayer.IPV4, new Ip4.Builder());
    NetworkLayer.register(NetworkLayer.IPV6, new Ip6.Builder());
    NetworkLayer.register(NetworkLayer.DOT1Q_VLAN_TAGGED_FRAMES, new Vlan.Builder());
    NetworkLayer.register(NetworkLayer.IEEE_802_1_AD, new Vlan.Builder());
    TransportLayer.register(TransportLayer.TCP, new Tcp.Builder());
    TransportLayer.register(TransportLayer.UDP, new Udp.Builder());
    TransportLayer.register(TransportLayer.ICMP, new Icmp4.Builder());
    TransportLayer.register(TransportLayer.IPV6, new Ip6.Builder());
    TransportLayer.register(TransportLayer.IPV6_ICMP, new Icmp6.Builder());
    TransportLayer.register(TransportLayer.IPV6_AH, new Authentication.Builder());
    TransportLayer.register(TransportLayer.IPV6_DSTOPT, new DestinationOptions.Builder());
    TransportLayer.register(TransportLayer.IPV6_ROUTING, new Routing.Builder());
    TransportLayer.register(TransportLayer.IPV6_FRAGMENT, new Fragment.Builder());
    TransportLayer.register(TransportLayer.IPV6_HOPOPT, new HopByHopOptions.Builder());
  }
}
