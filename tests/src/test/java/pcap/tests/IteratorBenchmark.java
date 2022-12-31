/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.tests;

import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import org.junit.jupiter.api.Assertions;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Measurement;
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

Benchmark                     Mode  Cnt         Score          Error  Units
IteratorBenchmark.forEach    thrpt    3  22396339.597 ±   338639.188  ops/s
IteratorBenchmark.forI       thrpt    3  21587777.836 ± 13118013.867  ops/s
IteratorBenchmark.forLoop    thrpt    3  21742206.645 ± 13691898.645  ops/s
IteratorBenchmark.whileLoop  thrpt    3  22447626.260 ±  2488246.744  ops/s
 */
public class IteratorBenchmark {

  public static void main(String[] args) throws RunnerException {
    Options opt =
        new OptionsBuilder().include(IteratorBenchmark.class.getSimpleName()).forks(1).build();

    new Runner(opt).run();
  }

  @Warmup(iterations = 2) // Warmup Iteration = 3
  @Measurement(iterations = 3)
  @Benchmark
  public void whileLoop() {
    List<Integer> integers = Arrays.asList(0, 1, 2, 3, 4, 5, 6, 7, 8, 9);
    final Iterator<Integer> iterator = integers.iterator();
    while (iterator.hasNext()) {
      int i = iterator.next();
      Assertions.assertTrue(i >= 0);
    }
  }

  @Warmup(iterations = 2) // Warmup Iteration = 3
  @Measurement(iterations = 3)
  @Benchmark
  public void forLoop() {
    List<Integer> integers = Arrays.asList(0, 1, 2, 3, 4, 5, 6, 7, 8, 9);
    for (Integer i : integers) {
      Assertions.assertTrue(i >= 0);
    }
  }

  @Warmup(iterations = 2) // Warmup Iteration = 3
  @Measurement(iterations = 3)
  @Benchmark
  public void forEach() {
    List<Integer> integers = Arrays.asList(0, 1, 2, 3, 4, 5, 6, 7, 8, 9);
    integers.forEach(i -> Assertions.assertTrue(i >= 0));
  }

  @Warmup(iterations = 2) // Warmup Iteration = 3
  @Measurement(iterations = 3)
  @Benchmark
  public void forI() {
    List<Integer> integers = Arrays.asList(0, 1, 2, 3, 4, 5, 6, 7, 8, 9);
    for (int i = 0; i < integers.size(); i++) {
      Assertions.assertTrue(integers.get(i) >= 0);
    }
  }
}
