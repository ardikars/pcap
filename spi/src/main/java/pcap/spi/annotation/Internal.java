/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * Indicates method, type, field, etc is {@code Unsafe} and only for internal usage and may change
 * at any time.
 *
 * @since 1.3.0
 */
@Documented
@Retention(RetentionPolicy.SOURCE)
public @interface Internal {}
