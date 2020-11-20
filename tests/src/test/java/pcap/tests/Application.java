/*
 * Copyright (c) 2020 Pcap <contact@pcap.ardikars.com>
 * SPDX-License-Identifier: MIT
 */
package pcap.tests;

import pcap.codec.ethernet.Ethernet;
import pcap.codec.ip.Ip4;
import pcap.codec.ip.Ip6;
import pcap.codec.tcp.Tcp;
import pcap.codec.udp.Udp;
import pcap.spi.*;
import pcap.spi.annotation.Async;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.TimeoutException;
import pcap.spi.exception.error.*;
import pcap.spi.option.DefaultLiveOptions;

public class Application {

  public static void main(String[] args)
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Service service = Service.Creator.create("PcapService");
    Interface devices = service.interfaces();
    for (Interface device : devices) {
      System.out.println(
          "[*] Device name   : " + device.name() + " (" + device.description() + ")");
    }
    System.out.println();
    System.out.println("[v] Chosen device : " + devices.name());
    try (Pcap live = service.live(devices, new DefaultLiveOptions().proxy(PcapProxy.class))) {
      PacketBuffer packetBuffer = live.allocate(PacketBuffer.class);
      PacketHeader packetHeader = live.allocate(PacketHeader.class);
      for (int i = 0; i < 10; i++) {
        try {
          live.nextEx(packetHeader, packetBuffer);
          System.out.println("[ PacketHeader:");
          System.out.println("\tTimestamp -> Second        : " + packetHeader.timestamp().second());
          System.out.println(
              "\tTimestamp -> Micro second  : " + packetHeader.timestamp().microSecond());
          System.out.println("\tCapture length             : " + packetHeader.captureLength());
          System.out.println("\tLength                     : " + packetHeader.length());
          System.out.println("]");
          System.out.println();
          Statistics statistics = live.stats();
          System.out.println("[ Statistics:");
          System.out.println("\tReceived                   : " + statistics.received());
          System.out.println("\tDropped                    : " + statistics.dropped());
          System.out.println("\tDropped by interface       : " + statistics.droppedByInterface());
          System.out.println("]");
          System.out.println();
          Ethernet ethernet =
              packetBuffer.byteOrder(PacketBuffer.ByteOrder.BIG_ENDIAN).cast(Ethernet.class);
          System.out.println(ethernet);
          if (ethernet.type() == Ip4.TYPE) {
            Ip4 ip4 = packetBuffer.readerIndex(ethernet.size()).cast(Ip4.class);
            System.out.println(ip4);
            if (ip4.protocol() == Tcp.TYPE) {
              Tcp tcp = packetBuffer.readerIndex(ethernet.size() + ip4.size()).cast(Tcp.class);
              System.out.println(tcp);
            } else if (ip4.protocol() == Udp.TYPE) {
              Udp udp = packetBuffer.readerIndex(ethernet.size() + ip4.size()).cast(Udp.class);
              System.out.println(udp);
            }
          } else if (ethernet.type() == Ip6.TYPE) {
            Ip6 ip6 = packetBuffer.readerIndex(ethernet.size()).cast(Ip6.class);
            System.out.println(ip6);
            if (ip6.nextHeader() == Tcp.TYPE) {
              Tcp tcp = packetBuffer.readerIndex(ethernet.size() + ip6.size()).cast(Tcp.class);
              System.out.println(tcp);
            } else if (ip6.nextHeader() == Udp.TYPE) {
              Udp udp = packetBuffer.readerIndex(ethernet.size() + ip6.size()).cast(Udp.class);
              System.out.println(udp);
            }
          }
        } catch (TimeoutException e) {
          System.err.println(e);
        } catch (BreakException e) {
          System.err.println(e);
        }
      }
    } catch (ErrorException e) {
      System.err.println(e);
    }
  }

  interface PcapProxy extends Pcap {

    @Async(timeout = 5000)
    @Override
    void nextEx(PacketHeader packetHeader, PacketBuffer packetBuffer)
        throws BreakException, ErrorException, TimeoutException;
  }
}
