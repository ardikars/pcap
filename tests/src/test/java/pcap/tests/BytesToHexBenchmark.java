/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.tests;

import java.util.Random;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;
import pcap.common.util.Strings;

public class BytesToHexBenchmark {

  private static final byte[] BYTES8 = new byte[8];
  private static final byte[] BYTES16 = new byte[16];
  private static final byte[] BYTES32 = new byte[32];
  private static final byte[] BYTES64 = new byte[64];
  private static final byte[] BYTES128 = new byte[128];
  private static final byte[] BYTES256 = new byte[256];
  private static final byte[] BYTES512 = new byte[512];
  private static final byte[] BYTES1024 = new byte[1024];
  private static final byte[] BYTES2048 = new byte[2048];
  private static final byte[] BYTES4096 = new byte[4096];
  private static final byte[] BYTES8192 = new byte[8192];

  static {
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
  }

  public static void main(String[] args) throws RunnerException {
    Options opt =
        new OptionsBuilder().include(BytesToHexBenchmark.class.getSimpleName()).forks(1).build();
    new Runner(opt).run();
  }

  @Warmup(iterations = 2) // Warmup Iteration = 3
  @Measurement(iterations = 3)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  public void bytes8ToHex() {
    Strings.hex(BYTES8);
  }

  @Warmup(iterations = 2) // Warmup Iteration = 3
  @Measurement(iterations = 3)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  public void bytes16ToHex() {
    Strings.hex(BYTES16);
  }

  @Warmup(iterations = 2) // Warmup Iteration = 3
  @Measurement(iterations = 3)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  public void bytes32ToHex() {
    Strings.hex(BYTES32);
  }

  @Warmup(iterations = 2) // Warmup Iteration = 3
  @Measurement(iterations = 3)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  public void bytes64ToHex() {
    Strings.hex(BYTES64);
  }

  @Warmup(iterations = 2) // Warmup Iteration = 3
  @Measurement(iterations = 3)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  public void bytes128ToHex() {
    Strings.hex(BYTES128);
  }

  @Warmup(iterations = 2) // Warmup Iteration = 3
  @Measurement(iterations = 3)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  public void bytes256ToHex() {
    Strings.hex(BYTES256);
  }

  @Warmup(iterations = 2) // Warmup Iteration = 3
  @Measurement(iterations = 3)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  public void bytes512ToHex() {
    Strings.hex(BYTES512);
  }

  @Warmup(iterations = 2) // Warmup Iteration = 3
  @Measurement(iterations = 3)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  public void bytes1024ToHex() {
    Strings.hex(BYTES1024);
  }

  @Warmup(iterations = 2) // Warmup Iteration = 3
  @Measurement(iterations = 3)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  public void bytes2048ToHex() {
    Strings.hex(BYTES2048);
  }

  @Warmup(iterations = 2) // Warmup Iteration = 3
  @Measurement(iterations = 3)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  public void bytes4096ToHex() {
    Strings.hex(BYTES4096);
  }

  @Warmup(iterations = 2) // Warmup Iteration = 3
  @Measurement(iterations = 3)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  public void bytes8192ToHex() {
    Strings.hex(BYTES8192);
  }
}
