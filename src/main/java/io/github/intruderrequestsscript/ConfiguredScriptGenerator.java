package io.github.intruderrequestsscript;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

final class ConfiguredScriptGenerator {
    private ConfiguredScriptGenerator() {
    }

    static String generate(RequestModel request, ScriptConfiguration configuration) {
        var template = IntruderRequestParser.parse(request.rawRequest());
        List<List<String>> sets = normalizedSets(configuration, template.positionCount());
        String scheme = request.scheme() == null || request.scheme().isBlank() ? "https" : request.scheme();
        int defaultPort = scheme.equalsIgnoreCase("https") ? 443 : 80;
        String authority = request.port() == defaultPort ? request.host() : request.host() + ":" + request.port();
        String baseUrl = scheme + "://" + authority;

        StringBuilder definitions = new StringBuilder();
        for (int i = 0; i < sets.size(); i++) {
            definitions.append("payloads_").append(i + 1).append(" = ").append(pyList(sets.get(i))).append("\n");
        }

        String scriptTemplate = """
                #!/usr/bin/env python3
                # Generated from an Intruder-style configuration. Authorized testing only.
                from __future__ import annotations

                import base64
                import concurrent.futures
                import itertools
                import threading
                import time
                import urllib.parse
                import requests
                from requests.adapters import HTTPAdapter
                from urllib3.util.retry import Retry

                BASE_URL = %s
                LITERALS = %s
                DEFAULTS = %s
                CONCURRENCY = %d
                DELAY_SECONDS = %.6f
                RETRIES = %d
                TIMEOUT_SECONDS = %d
                FOLLOW_REDIRECTS = %s
                VERIFY_TLS = %s
                PROCESSING_RULES = %s

                %s
                throttle_lock = threading.Lock()
                next_request_at = 0.0

                def process_payload(value):
                    for rule, first, second in PROCESSING_RULES:
                        if rule == "URL_ENCODE":
                            value = urllib.parse.quote_plus(value, safe="")
                        elif rule == "BASE64_ENCODE":
                            value = base64.b64encode(value.encode()).decode()
                        elif rule == "PREFIX":
                            value = first + value
                        elif rule == "SUFFIX":
                            value = value + first
                        elif rule == "REPLACE":
                            value = value.replace(first, second)
                    return value

                def payload_combinations():
                %s

                def build_raw_request(values):
                    values = [process_payload(str(value)) for value in values]
                    parts = []
                    for index, literal in enumerate(LITERALS[:-1]):
                        parts.extend((literal, values[index]))
                    parts.append(LITERALS[-1])
                    return "".join(parts)

                def wait_for_resource_pool():
                    global next_request_at
                    with throttle_lock:
                        now = time.monotonic()
                        if now < next_request_at:
                            time.sleep(next_request_at - now)
                        next_request_at = time.monotonic() + DELAY_SECONDS

                def send_raw(raw):
                    wait_for_resource_pool()
                    head, separator, body = raw.partition("\\r\\n\\r\\n")
                    if not separator:
                        head, separator, body = raw.partition("\\n\\n")
                    lines = head.replace("\\r\\n", "\\n").split("\\n")
                    method, target, _ = lines[0].split(" ", 2)
                    headers = {}
                    for line in lines[1:]:
                        if not line or ":" not in line:
                            continue
                        name, value = line.split(":", 1)
                        if name.lower() not in {"content-length", "host"}:
                            headers[name.strip()] = value.strip()
                    retry = Retry(total=RETRIES, connect=RETRIES, read=RETRIES, redirect=0,
                                  status=0, allowed_methods=None)
                    with requests.Session() as session:
                        session.mount("http://", HTTPAdapter(max_retries=retry))
                        session.mount("https://", HTTPAdapter(max_retries=retry))
                        response = session.request(method, BASE_URL + target, headers=headers,
                                                   data=body.encode("latin-1"),
                                                   allow_redirects=FOLLOW_REDIRECTS,
                                                   verify=VERIFY_TLS, timeout=TIMEOUT_SECONDS)
                    print(response.status_code, len(response.content), method, target)

                def main():
                    with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
                        futures = [executor.submit(send_raw, build_raw_request(values))
                                   for values in payload_combinations()]
                        for future in futures:
                            future.result()

                if __name__ == "__main__":
                    main()
                """;
        return String.format(Locale.ROOT, scriptTemplate,
                pyString(baseUrl), pyList(template.literals()), pyList(template.defaults()),
                configuration.concurrency(), configuration.delayMillis() / 1000.0, configuration.retries(),
                configuration.timeoutSeconds(), pyBool(configuration.followRedirects()), pyBool(configuration.verifyTls()),
                rules(configuration.processingRules()), definitions, combinations(configuration.mode(), template.positionCount(), sets.size()));
    }

    private static List<List<String>> normalizedSets(ScriptConfiguration config, int positions) {
        int required = config.mode() == AttackMode.SNIPER || config.mode() == AttackMode.BATTERING_RAM ? 1 : positions;
        List<List<String>> sets = new ArrayList<>();
        for (int i = 0; i < required; i++) {
            sets.add(i < config.payloadSets().size() ? config.payloadSets().get(i) : List.of());
        }
        return sets;
    }

    private static String combinations(AttackMode mode, int positions, int sets) {
        String i = "        ";
        return switch (mode) {
            case SNIPER -> i + "for position in range(" + positions + "):\n" + i + "    for payload in payloads_1:\n"
                    + i + "        values = DEFAULTS.copy()\n" + i + "        values[position] = payload\n" + i + "        yield values";
            case BATTERING_RAM -> i + "for payload in payloads_1:\n" + i + "    yield [payload] * " + positions;
            case PITCHFORK -> i + "yield from zip(" + names(sets) + ")";
            case CLUSTER_BOMB -> i + "yield from itertools.product(" + names(sets) + ")";
        };
    }

    private static String names(int count) {
        List<String> result = new ArrayList<>();
        for (int i = 1; i <= count; i++) result.add("payloads_" + i);
        return String.join(", ", result);
    }

    private static String rules(List<ScriptConfiguration.ProcessingRule> rules) {
        List<String> values = new ArrayList<>();
        for (var rule : rules) {
            values.add("(" + pyString(rule.type().name()) + ", " + pyString(rule.first()) + ", " + pyString(rule.second()) + ")");
        }
        return "[" + String.join(", ", values) + "]";
    }

    private static String pyList(List<String> values) {
        return "[" + values.stream().map(ConfiguredScriptGenerator::pyString).reduce((a, b) -> a + ", " + b).orElse("") + "]";
    }

    private static String pyString(String value) {
        return "'" + value.replace("\\", "\\\\").replace("'", "\\'").replace("\r", "\\r").replace("\n", "\\n") + "'";
    }

    private static String pyBool(boolean value) { return value ? "True" : "False"; }
}
