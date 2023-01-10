/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.jdk7.internal;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import java.lang.ref.PhantomReference;
import java.lang.ref.ReferenceQueue;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import pcap.common.util.Strings;
import pcap.spi.PacketBuffer;
import pcap.spi.PacketFilter;
import pcap.spi.exception.ErrorException;
import pcap.spi.util.Consumer;

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
  public void dump(Consumer<String> consumer) {
    checkOpenState();
    fp.bf_insns.read();
    final int n = fp.bf_len;
    NativeMappings.bpf_insn.ByReference insn = fp.bf_insns;
    int size = insn.size();
    for (int i = 0; i < n; i++) {
      consumer.accept(NativeMappings.bpf_image(insn, i));
      final Pointer pointer = insn.getPointer().share(size);
      insn = new NativeMappings.bpf_insn.ByReference(pointer);
      insn.read();
    }
  }

  @Override
  public byte[] bytes() {
    checkOpenState();
    fp.bf_insns.read();
    final int n = fp.bf_len;
    NativeMappings.bpf_insn.ByReference insn = fp.bf_insns;
    final int size = insn.size();
    final ByteBuffer buffer = ByteBuffer.allocate(size * n + 4);
    buffer.putInt(n);
    for (int i = 0; i < n; i++) {
      buffer.putShort(insn.code);
      buffer.put(insn.jt);
      buffer.put(insn.jf);
      buffer.putInt(insn.k);
      final Pointer pointer = insn.getPointer().share(size);
      insn = new NativeMappings.bpf_insn.ByReference(pointer);
      insn.read();
    }
    return buffer.array();
  }

  @Override
  public void close() throws Exception {
    checkOpenState();
    NativeMappings.pcap_freecode(fp);
    cleaner.pointer = 0L;
  }

  @Override
  public String toString() {
    try {
      return Strings.hex(bytes());
    } catch (Exception e) {
      return "";
    }
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
