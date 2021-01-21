/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Required minimal native pcap library version for specific functions.
 *
 * @since 1.0.0
 */
@Incubating
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Version {

  /**
   * Get minimal required major version.
   *
   * @return returns minimal required major version.
   * @since 1.0.0
   */
  int major();

  /**
   * Get minimal required minor version.
   *
   * @return returns minimal required minor version.
   * @since 1.0.0
   */
  int minor();

  /**
   * Get minimal required patch version.
   *
   * @return returns minimal required patch version.
   * @since 1.0.0
   */
  int patch();
}
