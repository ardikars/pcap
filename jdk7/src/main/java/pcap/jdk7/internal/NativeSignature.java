/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.jdk7.internal;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import pcap.spi.annotation.Version;

@Target(ElementType.METHOD)
@Retention(RetentionPolicy.SOURCE)
public @interface NativeSignature {

  /**
   * Get native function signature.
   *
   * @return returns native function signature.
   * @since 1.2.1
   */
  String signature();

  /**
   * Added in native library since version.
   *
   * @return returns {@link Version}.
   * @since 1.2.1
   */
  Version since();

  /**
   * Get description of specific functions.
   *
   * @return returns description of specific functions.
   * @since 1.2.1
   */
  String description() default "";

  /**
   * Indicate this function is compatible for different platform.
   *
   * @return returns {@code true} if portable, {@code false} otherwise.
   * @since 1.2.1
   */
  boolean portable() default true;
}
