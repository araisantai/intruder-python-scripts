package io.github.intruderrequestsscript;

public enum AttackMode {
    SNIPER("Sniper"),
    BATTERING_RAM("Battering ram"),
    PITCHFORK("Pitchfork"),
    CLUSTER_BOMB("Cluster bomb");

    private final String label;

    AttackMode(String label) {
        this.label = label;
    }

    @Override
    public String toString() {
        return label;
    }
}
