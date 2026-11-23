package com.pqcaps.scanner;

import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.*;

/**
 * Loads and provides lookup access to rules defined in {@code rules.yaml}.
 */
public final class RuleRegistry {

    private static final RuleRegistry INSTANCE = new RuleRegistry();

    private final Map<String, Rule> rulesById = new LinkedHashMap<>();

    public RuleRegistry() {
        loadDefaultRules();
    }

    public static RuleRegistry getInstance() {
        return INSTANCE;
    }

    @SuppressWarnings("unchecked")
    private void loadDefaultRules() {
        try (InputStream in = getClass().getResourceAsStream("/rules.yaml")) {
            if (in == null) {
                System.err.println("[RuleRegistry] Warning: /rules.yaml not found on classpath!");
                return;
            }
            parseYaml(in);
        } catch (Exception e) {
            System.err.println("[RuleRegistry] Failed to load /rules.yaml: " + e.getMessage());
        }
    }

    public void loadFromFile(File file) {
        try (InputStream in = new FileInputStream(file)) {
            rulesById.clear();
            parseYaml(in);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load rules from file " + file.getAbsolutePath(), e);
        }
    }

    @SuppressWarnings("unchecked")
    private void parseYaml(InputStream in) {
        Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));
        Map<String, Object> data = yaml.load(in);
        if (data == null || !data.containsKey("rules")) {
            return;
        }

        List<Map<String, Object>> rulesList = (List<Map<String, Object>>) data.get("rules");
        for (Map<String, Object> r : rulesList) {
            String id = (String) r.get("id");
            String name = (String) r.get("name");
            String category = (String) r.get("category");
            boolean qv = Boolean.TRUE.equals(r.get("quantumVulnerable"));
            String severity = (String) r.get("severity");
            int baseScore = r.containsKey("baseScore") ? ((Number) r.get("baseScore")).intValue() : 0;
            String explanation = (String) r.get("explanation");
            String recommendation = (String) r.get("recommendation");
            String migrationTarget = (String) r.get("migrationTarget");

            Rule rule = new Rule(id, name, category, qv, severity, baseScore, explanation, recommendation, migrationTarget);
            rulesById.put(id, rule);
        }
    }

    public Rule getRule(String id) {
        return rulesById.get(id);
    }

    public Collection<Rule> getAllRules() {
        return Collections.unmodifiableCollection(rulesById.values());
    }
}
