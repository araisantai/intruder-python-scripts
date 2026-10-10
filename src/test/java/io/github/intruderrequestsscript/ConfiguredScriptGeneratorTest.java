package io.github.intruderrequestsscript;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ConfiguredScriptGeneratorTest {
    private static final RequestModel REQUEST = new RequestModel(
            "POST /login HTTP/1.1\r\nHost: example.test\r\n\r\nu=§guest§&p=§password§",
            "https", "example.test", 443);

    @Test
    void generatesEveryAttackModeWithRuntimeSettings() {
        for (AttackMode mode : AttackMode.values()) {
            var config = new ScriptConfiguration(mode,
                    List.of(List.of("a", "b"), List.of("1", "2")),
                    List.of(new ScriptConfiguration.ProcessingRule(
                            ScriptConfiguration.RuleType.PREFIX, "pre-", "")),
                    7, 125, 2, 20, true, false);
            String script = ConfiguredScriptGenerator.generate(REQUEST, config);
            assertThat(script).contains("CONCURRENCY = 7", "DELAY_SECONDS = 0.125000",
                    "RETRIES = 2", "FOLLOW_REDIRECTS = True", "PREFIX");
        }
    }

    @Test
    void rejectsRequestWithoutPositions() {
        var request = new RequestModel("GET / HTTP/1.1\r\n\r\n", "https", "example.test", 443);
        var config = new ScriptConfiguration(AttackMode.SNIPER, List.of(List.of("x")), List.of(),
                1, 0, 0, 30, false, false);
        assertThatThrownBy(() -> ConfiguredScriptGenerator.generate(request, config))
                .hasMessageContaining("payload positions");
    }

    @Test
    void reconstructsMarkersFromBurpByteOffsets() {
        String raw = "GET /users/guest?id=1 HTTP/1.1\r\n\r\n";
        String marked = PayloadPositionExtractor.addSectionSigns(raw,
                List.of(new PayloadPositionExtractor.Offset(11, 16),
                        new PayloadPositionExtractor.Offset(20, 21)));
        assertThat(marked).isEqualTo("GET /users/§guest§?id=§1§ HTTP/1.1\r\n\r\n");
    }
}
