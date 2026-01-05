/**
 * Auto Remediation Bot – Single File Version
 * Objetivo: otimizar trabalho manual, NÃO resolver 100%
 */

const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

const ROOT = path.resolve(__dirname, "../../");
const REPORT = path.join(ROOT, "report.json");
const POM = path.join(ROOT, "pom.xml");

/* -------------------- UTIL -------------------- */

function runMaven(cmd) {
  try {
    const out = execSync(cmd, {
      cwd: ROOT,
      encoding: "utf8",
      stdio: "pipe"
    });
    return { status: "OK", output: out };
  } catch (e) {
    const out = e.stdout?.toString() || "";
    if (out.includes("Could not find artifact")) {
      return { status: "UNRESOLVABLE_ARTIFACT", output: out };
    }
    return { status: "ERROR", output: out };
  }
}

function parseTree(raw) {
  if (!raw) return [];
  return raw
    .split("\n")
    .filter(l => l.includes(":jar:"))
    .map(l => {
      const m = l.match(/([\w\.\-]+):([\w\.\-]+):jar:([\w\.\-]+)/);
      if (!m) return null;
      return {
        ga: `${m[1]}:${m[2]}`,
        version: m[3]
      };
    })
    .filter(Boolean);
}

/* -------------------- MEND PARSER -------------------- */

function parseMend(report) {
  return report.libraries
    .filter(l => l.vulnerabilities && l.vulnerabilities.length > 0)
    .map(l => {
      const fix = l.vulnerabilities[0]?.topFix?.fixResolution || "";
      const fixedVersion = fix.split(":").pop();

      return {
        ga: `${l.groupId}:${l.artifactId}`,
        currentVersion: l.version,
        fixedVersion
      };
    });
}

/* -------------------- POM MUTATION -------------------- */

function addDependencyManagement(ga, version) {
  const [groupId, artifactId] = ga.split(":");
  let pom = fs.readFileSync(POM, "utf8");

  if (!pom.includes("<dependencyManagement>")) {
    pom = pom.replace(
      "</project>",
      `
  <dependencyManagement>
    <dependencies></dependencies>
  </dependencyManagement>
</project>`
    );
  }

  if (pom.includes(`<artifactId>${artifactId}</artifactId>`)) {
    return false; // já existe override
  }

  pom = pom.replace(
    "<dependencies>",
    `<dependencies>
      <dependency>
        <groupId>${groupId}</groupId>
        <artifactId>${artifactId}</artifactId>
        <version>${version}</version>
      </dependency>`
  );

  fs.writeFileSync(POM, pom);
  return true;
}

/* -------------------- CORE LOGIC -------------------- */

function autoRemediate() {
  const report = JSON.parse(fs.readFileSync(REPORT, "utf8"));
  const mendDeps = parseMend(report);

  const initialTree = runMaven("mvn -q dependency:tree");
  const treeBefore = parseTree(initialTree.output || "");

  const results = [];

  for (const dep of mendDeps) {
    const found = treeBefore.find(d => d.ga === dep.ga);

    if (!found) {
      results.push({
        ga: dep.ga,
        status: "UNMANAGED",
        reason: "Not present in dependency:tree"
      });
      continue;
    }

    const changed = addDependencyManagement(dep.ga, dep.fixedVersion);

    if (!changed) {
      results.push({
        ga: dep.ga,
        status: "SKIPPED",
        reason: "Already managed in POM"
      });
      continue;
    }

    const validation = runMaven(
      `mvn -q dependency:tree -Dincludes=${dep.ga}`
    );

    if (validation.status === "UNRESOLVABLE_ARTIFACT") {
      results.push({
        ga: dep.ga,
        attemptedVersion: dep.fixedVersion,
        status: "UNVERIFIABLE",
        reason: "Artifact not available in configured repositories"
      });
      continue;
    }

    if (validation.status !== "OK") {
      results.push({
        ga: dep.ga,
        status: "ERROR",
        reason: "Unexpected Maven error"
      });
      continue;
    }

    const treeAfter = parseTree(validation.output);
    const fixed = treeAfter.every(
      d => d.ga !== dep.ga || d.version === dep.fixedVersion
    );

    results.push({
      ga: dep.ga,
      from: dep.currentVersion,
      to: dep.fixedVersion,
      status: fixed ? "APPLIED" : "FAILED"
    });
  }

  fs.writeFileSync(
    path.join(ROOT, "auto-remediation-result.json"),
    JSON.stringify(results, null, 2)
  );

  console.log("✔ Auto remediation finished");
}

/* -------------------- RUN -------------------- */

autoRemediate();
