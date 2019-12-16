package br.com.challenge.enums;

public enum Environment {

    PROD(0, "PROD"),
    HML(1, "HML"),
    DEV(2, "DEV");

    private int cod;
    private String description;

    Environment(int cod, String description) {
        this.cod = cod;
        this.description = description;
    }

    public static Environment toEnum(Integer cod) {
        if (cod == null) {
            return null;
        }

        for (Environment environment : Environment.values()) {
            if (cod.equals(environment.getCod())) {
                return environment;
            }
        }

        throw new IllegalArgumentException("Invalid id: " + cod);
    }

    public int getCod() {
        return cod;
    }

    public String getDescription() {
        return description;
    }
}