/*
 * Copyright 2024 Netflix, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.netflix.spinnaker.kork.actuator.utils;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.springframework.boot.actuate.endpoint.SanitizableData;
import org.springframework.util.StringUtils;

public class SanitizerUtils {
  private static final String[] REGEX_PARTS = {"*", "$", "^", "+"};
  private static final Set<String> URI_USERINFO_KEYS =
      new LinkedHashSet<>(Arrays.asList("uri", "uris", "url", "urls", "address", "addresses"));

  private static final Pattern URI_USERINFO_PATTERN =
      Pattern.compile("^\\[?[A-Za-z][A-Za-z0-9+.\\-]+://.+:(.*)@.+$");

  public static Pattern getPattern(String value) {
    if (isRegex(value)) {
      return Pattern.compile(value, Pattern.CASE_INSENSITIVE);
    }
    return Pattern.compile(".*" + value + "$", Pattern.CASE_INSENSITIVE);
  }

  private static boolean isRegex(String value) {
    for (String part : REGEX_PARTS) {
      if (value.contains(part)) {
        return true;
      }
    }
    return false;
  }

  public static boolean keyIsUriWithUserInfo(Pattern pattern) {
    for (String uriKey : URI_USERINFO_KEYS) {
      if (pattern.matcher(uriKey).matches()) {
        return true;
      }
    }
    return false;
  }

  public static Object sanitizeUris(String value) {
    return Arrays.stream(value.split(","))
        .map(SanitizerUtils::sanitizeUri)
        .collect(Collectors.joining(","));
  }

  private static String sanitizeUri(String value) {
    Matcher matcher = URI_USERINFO_PATTERN.matcher(value);
    String password = matcher.matches() ? matcher.group(1) : null;
    if (password != null) {
      return StringUtils.replace(
          value, ":" + password + "@", ":" + SanitizableData.SANITIZED_VALUE + "@");
    }
    return value;
  }
}
