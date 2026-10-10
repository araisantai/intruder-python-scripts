package io.github.intruderrequestsscript;

import java.util.ArrayList;
import java.util.List;

final class IntruderRequestParser {
    private IntruderRequestParser() {
    }

    static ParsedTemplate parse(String rawRequest) {
        List<String> literals = new ArrayList<>();
        List<String> defaults = new ArrayList<>();
        int cursor = 0;
        while (true) {
            int open = rawRequest.indexOf('§', cursor);
            if (open < 0) {
                literals.add(rawRequest.substring(cursor));
                break;
            }
            int close = rawRequest.indexOf('§', open + 1);
            if (close < 0) {
                throw new IllegalArgumentException("The request has an unmatched § payload marker.");
            }
            literals.add(rawRequest.substring(cursor, open));
            defaults.add(rawRequest.substring(open + 1, close));
            cursor = close + 1;
        }
        if (defaults.isEmpty()) {
            throw new IllegalArgumentException("No Intruder payload positions were found. Add § markers first.");
        }
        return new ParsedTemplate(List.copyOf(literals), List.copyOf(defaults));
    }

    record ParsedTemplate(List<String> literals, List<String> defaults) {
        int positionCount() {
            return defaults.size();
        }
    }
}
