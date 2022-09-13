/*
 * Copyright (c) 2020-2022 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * Indicates that a feature is incubating (Unstable). This means that the feature is currently a
 * work-in-progress and may change at any time.
 *
 * @since 1.0.0
 */
@Documented
@Retention(RetentionPolicy.SOURCE)
public @interface Incubating {}
