/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.tests;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;
import pcap.common.util.Hexs;
import pcap.common.util.Strings;

import java.util.Random;

public class HexToBytesBenchmark {

  private static final String STR8;
  private static final String STR16;
  private static final String STR32;
  private static final String STR64;
  private static final String STR128;
  private static final String STR256;
  private static final String STR512;
  private static final String STR1024;
  private static final String STR2048;
  private static final String STR4096;
  private static final String STR8192;

  static {
    final byte[] BYTES8 = new byte[8];
    final byte[] BYTES16 = new byte[16];
    final byte[] BYTES32 = new byte[32];
    final byte[] BYTES64 = new byte[64];
    final byte[] BYTES128 = new byte[128];
    final byte[] BYTES256 = new byte[256];
    final byte[] BYTES512 = new byte[512];
    final byte[] BYTES1024 = new byte[1024];
    final byte[] BYTES2048 = new byte[2048];
    final byte[] BYTES4096 = new byte[4096];
    final byte[] BYTES8192 = new byte[8192];
    final Random random = new Random();
    random.nextBytes(BYTES8);
    random.nextBytes(BYTES16);
    random.nextBytes(BYTES32);
    random.nextBytes(BYTES64);
    random.nextBytes(BYTES128);
    random.nextBytes(BYTES256);
    random.nextBytes(BYTES512);
    random.nextBytes(BYTES1024);
    random.nextBytes(BYTES2048);
    random.nextBytes(BYTES4096);
    random.nextBytes(BYTES8192);
    STR8 = Strings.hex(BYTES8);
    STR16 = Strings.hex(BYTES8);
    STR32 = Strings.hex(BYTES8);
    STR64 = Strings.hex(BYTES8);
    STR128 = Strings.hex(BYTES8);
    STR256 = Strings.hex(BYTES8);
    STR512 = Strings.hex(BYTES8);
    STR1024 = Strings.hex(BYTES8);
    STR2048 = Strings.hex(BYTES8);
    STR4096 = Strings.hex(BYTES8);
    STR8192 = Strings.hex(BYTES8);
  }

  public static void main(String[] args) throws RunnerException {
    Options opt =
        new OptionsBuilder().include(HexToBytesBenchmark.class.getSimpleName()).forks(1).build();
    new Runner(opt).run();
  }

  @Warmup(iterations = 2) // Warmup Iteration = 3
  @Measurement(iterations = 3)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  public void str8ToBytes() {
    Hexs.parseHex(STR8);
  }

  @Warmup(iterations = 2) // Warmup Iteration = 3
  @Measurement(iterations = 3)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  public void str16ToBytes() {
    Hexs.parseHex(STR16);
  }

  @Warmup(iterations = 2) // Warmup Iteration = 3
  @Measurement(iterations = 3)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  public void str32ToBytes() {
    Hexs.parseHex(STR32);
  }

  @Warmup(iterations = 2) // Warmup Iteration = 3
  @Measurement(iterations = 3)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  public void str64ToBytes() {
    Hexs.parseHex(STR64);
  }

  @Warmup(iterations = 2) // Warmup Iteration = 3
  @Measurement(iterations = 3)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  public void str128ToBytes() {
    Hexs.parseHex(STR128);
  }

  @Warmup(iterations = 2) // Warmup Iteration = 3
  @Measurement(iterations = 3)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  public void str256ToBytes() {
    Hexs.parseHex(STR256);
  }

  @Warmup(iterations = 2) // Warmup Iteration = 3
  @Measurement(iterations = 3)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  public void str512ToBytes() {
    Hexs.parseHex(STR512);
  }

  @Warmup(iterations = 2) // Warmup Iteration = 3
  @Measurement(iterations = 3)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  public void str1024ToBytes() {
    Hexs.parseHex(STR1024);
  }

  @Warmup(iterations = 2) // Warmup Iteration = 3
  @Measurement(iterations = 3)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  public void str2048ToBytes() {
    Hexs.parseHex(STR2048);
  }

  @Warmup(iterations = 2) // Warmup Iteration = 3
  @Measurement(iterations = 3)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  public void str4096ToBytes() {
    Hexs.parseHex(STR4096);
  }

  @Warmup(iterations = 2) // Warmup Iteration = 3
  @Measurement(iterations = 3)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  public void str8192ToBytes() {
    Hexs.parseHex(STR8192);
  }
}
