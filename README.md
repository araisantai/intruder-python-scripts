# Intruder Python Scripts

A Burp Suite Montoya extension that turns an Intruder request into a configurable standalone Python `requests` script.

## Features

- Right-click menu only in the Intruder payload-position editor.
- Right-click actions for **Copy to clipboard** and **Save to file**.
- Burp-style configuration tabs for Positions, Payloads, Resource pool, and Settings.
- Sniper, Battering ram, Pitchfork, and Cluster bomb behavior.
- Per-position payload sets and ordered processing rules.
- Configurable concurrency, throttling, retries, timeout, redirects, and TLS verification.

## Build and install

Requirements: JDK 21 and Gradle 8+.

```bash
gradle clean test jar
```

In Burp, open **Extensions > Installed > Add**, choose **Java**, and select:

```text
build/libs/intruder-python-scripts-1.0.0.jar
```

The generated Python script needs Python 3 and `requests` (`python -m pip install requests`).

## Use

1. Configure payload positions in Intruder.
2. Right-click the payload-position editor and choose **Intruder Python Scripts**.
3. Choose **Copy to clipboard** or **Save to file**.
4. Complete the Burp-style configuration dialog and generate the script.

## Burp API limitation

Montoya 2026.7 exposes the request and payload positions, but not the active tab's payload generator, processing rules, resource pool, or attack-settings model. Those values therefore appear in the popup instead of being silently guessed. The extension does not require the Intruder attack to run before export.
