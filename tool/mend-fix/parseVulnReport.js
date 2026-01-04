// tools/auto-remediate/parseVulnReport.js
const fs = require("fs");

function extractVersion(fixResolution) {
  /**
   * Exemplo:
   * "Upgrade to version https://github.com/apache/commons-lang.git - commons-lang-3.18.0,org.apache.commons:commons-lang3:3.18.0"
   *
   * Queremos: 3.18.0
   */
  if (!fixResolution) return null;

  const match = fixResolution.match(/:([0-9]+(\.[0-9]+)+)/);
  return match ? match[1] : null;
}

function parseVulnReport(path) {
  const raw = JSON.parse(fs.readFileSync(path, "utf8"));

  if (!Array.isArray(raw.libraries)) {
    throw new Error("Relatório Mend inválido: campo 'libraries' ausente");
  }

  const fixes = new Map();

  for (const lib of raw.libraries) {
    if (
      !lib.groupId ||
      !lib.artifactId ||
      !Array.isArray(lib.vulnerabilities)
    ) {
      continue;
    }

    for (const vuln of lib.vulnerabilities) {
      const fixResolution = vuln?.topFix?.fixResolution;
      const fixedVersion = extractVersion(fixResolution);

      if (!fixedVersion) continue;

      const key = `${lib.groupId}:${lib.artifactId}`;

      // mantém sempre a maior versão sugerida
      if (
        !fixes.has(key) ||
        fixes.get(key).version < fixedVersion
      ) {
        fixes.set(key, {
          key,
          groupId: lib.groupId,
          artifactId: lib.artifactId,
          vulnerableVersion: lib.version,
          version: fixedVersion,
          cve: vuln.name,
          severity: vuln.severity
        });
      }
    }
  }

  if (fixes.size === 0) {
    throw new Error(
      "Nenhuma vulnerabilidade com fixResolution encontrada no relatório Mend"
    );
  }

  return [...fixes.values()];
}

module.exports = parseVulnReport;
