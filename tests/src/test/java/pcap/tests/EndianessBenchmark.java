/*
 * Copyright (c) 2020 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.tests;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;
import pcap.spi.PacketBuffer;

public class EndianessBenchmark {

  public static void main(String[] args) throws RunnerException {
    Options opt =
        new OptionsBuilder().include(EndianessBenchmark.class.getSimpleName()).forks(1).build();

    new Runner(opt).run();
  }

  @Warmup(iterations = 2) // Warmup Iteration = 3
  @Measurement(iterations = 3)
  @Benchmark
  public void withIf() {
    WithIf withIf = new WithIf();
    int i = 0;
    while (i < 99999) {
      withIf.change((i & 1) == 0);
      assert withIf.getInt() > 0;
      i++;
    }
    withIf.free();
  }

  @Warmup(iterations = 2) // Warmup Iteration = 3
  @Measurement(iterations = 3)
  @Benchmark
  public void withClass() {
    WithClass withClass = new WithClass();
    int i = 0;
    while (i < 99999) {
      assert (i & 1) < 2;
      assert withClass.getInt() > 0;
      i++;
    }
    withClass.free();
  }

  @Warmup(iterations = 2) // Warmup Iteration = 3
  @Measurement(iterations = 3)
  @Benchmark
  public void withEnumIf() {
    WithEnumIf withEnumIf = new WithEnumIf();
    int i = 0;
    while (i < 99999) {
      withEnumIf.change(
          (i & 1) == 0 ? PacketBuffer.ByteOrder.BIG_ENDIAN : PacketBuffer.ByteOrder.LITTLE_ENDIAN);
      assert withEnumIf.getInt() > 0;
      i++;
    }
    withEnumIf.free();
  }

  static final class WithClass {

    private final Pointer pointer;

    WithClass() {
      this.pointer = new Pointer(Native.malloc(4));
      this.pointer.setInt(0, 5);
    }

    public int getInt() {
      return Integer.reverseBytes(pointer.getInt(0));
    }

    void free() {
      Native.free(Pointer.nativeValue(pointer));
    }
  }

  static final class WithIf {

    private final Pointer pointer;

    private boolean isBe;

    WithIf() {
      this.pointer = new Pointer(Native.malloc(4));
      this.pointer.setInt(0, 5);
      this.isBe = false;
    }

    public int getInt() {
      if (isBe) {
        return pointer.getInt(0);
      } else {
        return Integer.reverseBytes(pointer.getInt(0));
      }
    }

    void change(boolean val) {
      this.isBe = val;
    }

    void free() {
      Native.free(Pointer.nativeValue(pointer));
    }
  }

  static final class WithEnumIf {

    private final Pointer pointer;

    private PacketBuffer.ByteOrder bo;

    WithEnumIf() {
      this.pointer = new Pointer(Native.malloc(4));
      this.pointer.setInt(0, 5);
      this.bo = PacketBuffer.ByteOrder.BIG_ENDIAN;
    }

    public int getInt() {
      if (bo == PacketBuffer.ByteOrder.BIG_ENDIAN) {
        return pointer.getInt(0);
      } else {
        return Integer.reverseBytes(pointer.getInt(0));
      }
    }

    void change(PacketBuffer.ByteOrder bo) {
      this.bo = bo;
    }

    void free() {
      Native.free(Pointer.nativeValue(pointer));
    }
  }
}
