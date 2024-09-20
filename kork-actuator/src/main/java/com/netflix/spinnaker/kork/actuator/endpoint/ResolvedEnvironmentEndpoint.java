/*
 * Copyright 2020 Netflix, Inc.
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
 *
 */
package com.netflix.spinnaker.kork.actuator.endpoint;

import static java.lang.String.format;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.endpoint.SanitizableData;
import org.springframework.boot.actuate.endpoint.Sanitizer;
import org.springframework.boot.actuate.endpoint.SanitizingFunction;
import org.springframework.boot.actuate.endpoint.annotation.Endpoint;
import org.springframework.boot.actuate.endpoint.annotation.ReadOperation;
import org.springframework.core.env.*;
import org.springframework.util.StringUtils;

@Endpoint(id = "resolvedEnv")
public class ResolvedEnvironmentEndpoint {

  private final Sanitizer sanitizer;
  private final Environment environment;
  private static final String[] REGEX_PARTS = {"*", "$", "^", "+"};
  private static final Set<String> URI_USERINFO_KEYS =
      new LinkedHashSet<>(Arrays.asList("uri", "uris", "url", "urls", "address", "addresses"));

  private static final Pattern URI_USERINFO_PATTERN =
      Pattern.compile("^\\[?[A-Za-z][A-Za-z0-9+.\\-]+://.+:(.*)@.+$");

  @Autowired
  public ResolvedEnvironmentEndpoint(
      Environment environment, ResolvedEnvironmentConfigurationProperties properties) {
    this.environment = environment;
    List<SanitizingFunction> sanitizingFunctions = new ArrayList<>();
    Optional.ofNullable(properties.getKeysToSanitize())
        .orElse(new ArrayList<>())
        .forEach(
            p ->
                sanitizingFunctions.add(
                    (data) -> {
                      Pattern pattern = getPattern(p);
                      if (pattern.matcher(data.getKey()).matches()) {
                        if (keyIsUriWithUserInfo(pattern)) {
                          return data.withValue(sanitizeUris(data.getValue().toString()));
                        }
                        return data.withValue(SanitizableData.SANITIZED_VALUE);
                      }
                      return data;
                    }));
    sanitizer = new Sanitizer(sanitizingFunctions);
  }

  private Pattern getPattern(String value) {
    if (isRegex(value)) {
      return Pattern.compile(value, Pattern.CASE_INSENSITIVE);
    }
    return Pattern.compile(".*" + value + "$", Pattern.CASE_INSENSITIVE);
  }

  private boolean isRegex(String value) {
    for (String part : REGEX_PARTS) {
      if (value.contains(part)) {
        return true;
      }
    }
    return false;
  }

  private boolean keyIsUriWithUserInfo(Pattern pattern) {
    for (String uriKey : URI_USERINFO_KEYS) {
      if (pattern.matcher(uriKey).matches()) {
        return true;
      }
    }
    return false;
  }

  private Object sanitizeUris(String value) {
    return Arrays.stream(value.split(",")).map(this::sanitizeUri).collect(Collectors.joining(","));
  }

  private String sanitizeUri(String value) {
    Matcher matcher = URI_USERINFO_PATTERN.matcher(value);
    String password = matcher.matches() ? matcher.group(1) : null;
    if (password != null) {
      return StringUtils.replace(
          value, ":" + password + "@", ":" + SanitizableData.SANITIZED_VALUE + "@");
    }
    return value;
  }

  @ReadOperation
  public Map<String, Object> resolvedEnv() {
    return getPropertyKeys().stream()
        .collect(
            Collectors.toMap(
                property -> property,
                property -> {
                  try {
                    return sanitizer.sanitize(
                        new SanitizableData(null, property, environment.getProperty(property)),
                        true);
                  } catch (Exception e) {
                    return format("Exception occurred: %s", e.getMessage());
                  }
                }));
  }

  /** This gathers all defined properties in the system (no matter the source) */
  private SortedSet<String> getPropertyKeys() {
    SortedSet<String> result = new TreeSet<>();
    MutablePropertySources sources;

    if (environment instanceof ConfigurableEnvironment) {
      sources = ((ConfigurableEnvironment) environment).getPropertySources();
    } else {
      sources = new StandardEnvironment().getPropertySources();
    }

    sources.forEach(
        source -> {
          if (source instanceof EnumerablePropertySource) {
            result.addAll(Arrays.asList(((EnumerablePropertySource<?>) source).getPropertyNames()));
          }
        });

    return result;
  }
}
