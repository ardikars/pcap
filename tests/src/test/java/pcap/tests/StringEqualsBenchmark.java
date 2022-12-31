/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.tests;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

/*
# uname -a
Linux unknown 5.11.0-37-generic #41~20.04.2-Ubuntu SMP Fri Sep 24 09:06:38 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux

# free -m
              total        used        free      shared  buff/cache   available
Mem:           7829        5879         146         695        1804        1057
Swap:          2047        1165         882

# lscpu | grep  'CPU(s):'
CPU(s):                          8
NUMA node0 CPU(s):               0-7

Benchmark                              Mode  Cnt           Score            Error  Units
StringEqualsBenchmark.compareToBench  thrpt    3  2117680726.490 ± 1426150987.276  ops/s
StringEqualsBenchmark.equalsBench     thrpt    3  1775442270.481 ± 5243182780.346  ops/s
 */
public class StringEqualsBenchmark {

  public static void main(String[] args) throws RunnerException {
    Options opt =
        new OptionsBuilder().include(StringEqualsBenchmark.class.getSimpleName()).forks(1).build();
    new Runner(opt).run();
  }

  @Warmup(iterations = 2) // Warmup Iteration = 3
  @Measurement(iterations = 3)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  public void equalsBench() {
    String a = "ABCDEFghijklmn0123456789";
    String b = "ABCDEFghijklmn0123456789";
    assert a.equals(b);
  }

  @Warmup(iterations = 2) // Warmup Iteration = 3
  @Measurement(iterations = 3)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  public void compareToBench() {
    String a = "ABCDEFghijklmn0123456789";
    String b = "ABCDEFghijklmn0123456789";
    assert a.compareTo(b) == 0;
  }
}
