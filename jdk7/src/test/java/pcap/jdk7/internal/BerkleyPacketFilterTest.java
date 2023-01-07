/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.jdk7.internal;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import pcap.common.util.Hexs;
import pcap.spi.Interface;
import pcap.spi.PacketBuffer;
import pcap.spi.PacketFilter;
import pcap.spi.Pcap;
import pcap.spi.Service;
import pcap.spi.option.DefaultLiveOptions;
import pcap.spi.util.Consumer;

class BerkleyPacketFilterTest extends BaseTest {

  @Test
  void clean() throws Exception {
    Service service = Service.Creator.create("PcapService");
    Interface lo = loopbackInterface(service);
    try (Pcap live = service.live(lo, new DefaultLiveOptions())) {
      BerkeleyPacketFilter bpf = (BerkeleyPacketFilter) live.compile("icmp", false);
      Assertions.assertNotNull(bpf);
      bpf.clean();
    }
  }

  @Test
  void dump() throws Exception {
    Service service = Service.Creator.create("PcapService");
    Interface lo = loopbackInterface(service);
    try (Pcap live = service.live(lo, new DefaultLiveOptions())) {
      BerkeleyPacketFilter bpf = (BerkeleyPacketFilter) live.compile("icmp", false);
      final StringBuilder sb = new StringBuilder();
      bpf.dump(
          new Consumer<String>() {
            @Override
            public void accept(String s) {
              sb.append(s).append('\n');
            }
          });
      String icmpHumanReadable =
          "(000) ldh      [12]\n(001) jeq      #0x800           jt 2\tjf 5\n(002) ldb      [23]\n(003) jeq      #0x1             jt 4\tjf 5\n(004) ret      #65535\n(005) ret      #0\n";
      Assertions.assertEquals(icmpHumanReadable, sb.toString());
      String icmpByteCode =
          "6\n40 0 0 12\n21 0 3 2048\n48 0 0 23\n21 0 1 1\n6 0 0 65535\n6 0 0 0\n";
      Assertions.assertEquals(icmpByteCode, bpf.toString());
      Assertions.assertNotNull(bpf);
      bpf.clean();
    }
  }

  @Test
  void close() throws Exception {
    Service service = Service.Creator.create("PcapService");
    Interface lo = loopbackInterface(service);
    try (Pcap live = service.live(lo, new DefaultLiveOptions())) {
      final BerkeleyPacketFilter icmp = (BerkeleyPacketFilter) live.compile("icmp", false);
      icmp.checkOpenState();
      icmp.close();
      Assertions.assertThrows(
          IllegalStateException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              icmp.close();
            }
          });
    }
  }

  @Test
  void filter() throws Exception {
    String hexStream =
        "b09575e41120e86f38393dbf0800450003e60000400040114e51c0a844aa8efb5468e64a01bb03d274134bb0e3e050f8b35a5e0f6beef76dcdf8b9b0d3e59849b0ae4a950336db453a20be53b16a75cf154d06f8a1b78e1b00c0eaa75e4c30e1b89ad19b3e4e249e3f87c97088da455d556905a551a086f388223a88a5179978eeb34aa67cb01883c3605382e5a5da21c4f699b07fc19492c0a464480f6e0a77f288992d21b03ac6a83a7f6f9b013c37544ddcbc7f4873d7c55beb7fc6c997130583ca2ffe5d2487a0c9097b82b331843fc11312f81c73a17d09902b32d5e0ed04e504b18d506f2d09e38144f5d19eb46c8c0d1547a88c8f97c57fb3051e8f7ae9807befbffb65b7a20adc105377ef5505c9f86cbcc7e1dfcbb3145ef28f1d6d3ecb2bb1583222a06acf30eed06e29deaad21d3a4f8a58c515d6d1028c0d2fae586d797ad03981ea73ba78dd920f3d2149b72d28c18cf76ef39e330a82a9c212a1906a974fd3b11d1b260ad9a34cca808dc80f0d7c4894dc3ca771be2c1cc0aa589efa8ffe1f79b9fac34e85b2daaaf612b5f921cf6d889503669801f692745b67b5b32a99522e25f0e5f08fb2685c0a579a3d38dd7ebe892b5846493da81fd940725ae8137923fd753a1e4b697144e395bdc964feb18c7e0b6e2ee4faefeb8edbd8c535b8be5c1bf14c5e10636ead8aba38a912e7805aad5b09415660453ba0d74771010b64f276c85f91559bad774b5c699cdfc7a0a4199a2d06732451b0f3d51c797c774a1b9b2f684fd7c64350ebcab4fed87f70e0f384c055be9899c326b92c53d0d6ae7ee63b076e18e05384bbe0bd830f3e20a5102f326a6415051b45c15f20725c5e4e20bcb03593a6bcd8150cff1cafdce54b3a2194609030a1064eb8f51dd5ceb205bb451baf620f65f81b1978c23d5e50ec65622c46b6438683d616be1b835403034ad03423238da42001a3379caa97b0ee4539caa214df900649b486e71211bc459d79ac791e8d5f4fc95c9a51e66dac84daf7a2ff2449de8b409ae32d873ce682a853d20ce704518da7570e250d22ea44c6565c2e201cbb171c0888024c2e72fc878e6ae069d55b518763887e8074c3fcf6f2d721d95b035459624de9322ae9199720e8d5684442e9461905685034a15e51b098f85fd93cd4e3b7290a654e22839b047a773169e701955a8fef8e350c673f286c50f62d143f5c6467568337f6954c0dde7cb6ca500dac2609a056620180e49740db33786cf5a79c5f0328fae3e23c767dd7519ea3ddd4a4b77060a567fdb6acb5eee89aa5f69964015e71d7df72f7127c3717b4d911258ef416e264662bf559956df84ed6a1e7f71c5b4b40a5fe7bfdca3d0da35310aa274a771f0f084f6e5ae6270227f2364d1b3e5fe27deab67bbd43bf1095b529293729261c";
    byte[] bytes = Hexs.parseHex(hexStream);
    Service service = Service.Creator.create("PcapService");
    Interface lo = ethernetInterface(service);
    try (Pcap live = service.live(lo, new DefaultLiveOptions())) {
      PacketBuffer buffer = live.allocate(PacketBuffer.class).capacity(bytes.length);
      buffer.writeBytes(bytes);
      try (PacketFilter filter = live.compile("udp port 443", true)) {
        Assertions.assertTrue(filter.filter(buffer));
      }
      try (PacketFilter filter = live.compile("udp port 53", true)) {
        Assertions.assertFalse(filter.filter(buffer));
      }
      Assertions.assertTrue(buffer.release());
    }
  }
}
