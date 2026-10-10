package io.github.intruderrequestsscript;

import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

final class PayloadPositionExtractor {
    private PayloadPositionExtractor() {
    }

    static String requestWithMarkers(HttpRequestResponse requestResponse) {
        HttpRequest request = requestResponse.request();
        String visibleRequest = request.toString();
        if (visibleRequest.indexOf('§') >= 0) return visibleRequest;

        List<Marker> markers = new ArrayList<>(requestResponse.requestMarkers());
        if (markers.isEmpty()) markers.addAll(request.markers());
        if (markers.isEmpty()) return visibleRequest;

        // Marker ranges are byte offsets into the raw HTTP message. ISO-8859-1 keeps
        // one Java character per byte, so inserting section signs does not shift them.
        String raw = new String(request.toByteArray().getBytes(), StandardCharsets.ISO_8859_1);
        return addSectionSigns(raw, markers.stream()
                .map(marker -> new Offset(marker.range().startIndexInclusive(), marker.range().endIndexExclusive()))
                .toList());
    }

    static String addSectionSigns(String raw, List<Offset> suppliedOffsets) {
        List<Offset> offsets = suppliedOffsets.stream()
                .sorted(Comparator.comparingInt(Offset::start).reversed())
                .toList();
        StringBuilder marked = new StringBuilder(raw);
        int nextStart = raw.length();
        for (Offset offset : offsets) {
            if (offset.start() < 0 || offset.end() < offset.start() || offset.end() > raw.length()) {
                throw new IllegalArgumentException("Burp returned an invalid payload-position range.");
            }
            if (offset.end() > nextStart) {
                throw new IllegalArgumentException("Burp returned overlapping payload positions.");
            }
            marked.insert(offset.end(), '§');
            marked.insert(offset.start(), '§');
            nextStart = offset.start();
        }
        return marked.toString();
    }

    record Offset(int start, int end) {
    }
}
