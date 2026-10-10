package io.github.intruderrequestsscript;

import java.util.List;

record ScriptConfiguration(
        AttackMode mode,
        List<List<String>> payloadSets,
        List<ProcessingRule> processingRules,
        int concurrency,
        long delayMillis,
        int retries,
        int timeoutSeconds,
        boolean followRedirects,
        boolean verifyTls
) {
    enum RuleType {
        URL_ENCODE("URL-encode"),
        BASE64_ENCODE("Base64-encode"),
        PREFIX("Add prefix"),
        SUFFIX("Add suffix"),
        REPLACE("Match/replace");

        private final String label;

        RuleType(String label) { this.label = label; }
        @Override public String toString() { return label; }
    }

    record ProcessingRule(RuleType type, String first, String second) {
        @Override public String toString() {
            return switch (type) {
                case URL_ENCODE, BASE64_ENCODE -> type.toString();
                case PREFIX, SUFFIX -> type + ": " + first;
                case REPLACE -> type + ": " + first + " → " + second;
            };
        }
    }
}
