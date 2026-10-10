package io.github.intruderrequestsscript;

public record RequestModel(String rawRequest, String scheme, String host, int port) {
}
