/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.jdk7.internal;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import java.lang.ref.PhantomReference;
import java.lang.ref.ReferenceQueue;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import pcap.spi.PacketBuffer;
import pcap.spi.PacketFilter;
import pcap.spi.exception.ErrorException;

class BerkeleyPacketFilter implements PacketFilter {

  static final Set<BpfReference> REFS = Collections.synchronizedSet(new HashSet<BpfReference>());
  static final ReferenceQueue<BerkeleyPacketFilter> RQ = new ReferenceQueue<BerkeleyPacketFilter>();

  final NativeMappings.bpf_program fp;
  final BpfReference cleaner;

  BerkeleyPacketFilter(Pointer pcap, String filter, boolean optimize, int netmask)
      throws ErrorException {
    Utils.requireNonBlank(filter, "filter: null (expected: filter != null && notBlank(filter))");
    int rc;
    this.fp = new NativeMappings.bpf_program();

    if (Utils.isSupported(1, 8, 0)) {
      // in libpcap 1.8.0 and later is newly thread-safe.
      rc = NativeMappings.pcap_compile(pcap, fp, filter, optimize ? 1 : 0, netmask);
    } else {
      synchronized (this) {
        rc = NativeMappings.pcap_compile(pcap, fp, filter, optimize ? 1 : 0, netmask);
      }
    }
    if (rc != NativeMappings.OK) {
      NativeMappings.pcap_freecode(fp);
      throw new ErrorException(NativeMappings.pcap_geterr(pcap).getString(0));
    }
    this.cleaner = new BpfReference(Pointer.nativeValue(fp.getPointer()), this, RQ);
    REFS.add(cleaner);
    clean();
  }

  void clean() {
    BpfReference cleaned;
    while ((cleaned = (BpfReference) RQ.poll()) != null) {
      if (cleaned.pointer > 0L) {
        NativeMappings.bpf_program bpfProgram = cleaned.asBpf();
        NativeMappings.pcap_freecode(bpfProgram);
        cleaned.pointer = 0L;
      }
    }
  }

  @Override
  public boolean filter(PacketBuffer packetBuffer) {
    checkOpenState();
    final int packetLength = (int) (packetBuffer.readableBytes());
    final DefaultPacketBuffer buffer = (DefaultPacketBuffer) packetBuffer;
    final long r =
        NativeMappings.bpf_filter(
            fp.bf_insns,
            buffer.buffer.share(buffer.readerIndex()),
            packetLength,
            (int) buffer.capacity());
    // not sure about this
    return r != 0 && r != 4294967295L;
  }

  @Override
  public void close() throws Exception {
    checkOpenState();
    NativeMappings.pcap_freecode(fp);
    cleaner.pointer = 0L;
  }

  void checkOpenState() {
    if (cleaner.pointer == 0L) {
      throw new IllegalStateException("Bpf program is closed.");
    }
  }

  static final class BpfReference extends PhantomReference<BerkeleyPacketFilter> {

    private long pointer;

    public BpfReference(
        long pointer,
        BerkeleyPacketFilter referent,
        ReferenceQueue<? super BerkeleyPacketFilter> q) {
      super(referent, q);
      this.pointer = pointer;
    }

    NativeMappings.bpf_program asBpf() {
      return Structure.newInstance(NativeMappings.bpf_program.class, new Pointer(pointer));
    }
  }
}
