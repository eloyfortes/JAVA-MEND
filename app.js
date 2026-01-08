/* ===============================
   DOM
================================ */
const dom = {
  pomInput: document.getElementById("pomInput"),
  treeInput: document.getElementById("treeInput"),
  mendInput: document.getElementById("mendInput"),
  pomOutput: document.getElementById("pomOutput"),
  overrideOutput: document.getElementById("overrideOutput"),
  warningsArea: document.getElementById("warningsArea"),
  useExclude: document.getElementById("useExclude"),
  generateBtn: document.getElementById("generateBtn"),
  strategyBox: document.getElementById("strategyBox"),
  strategyText: document.getElementById("strategyText"),
  strategySnippet: document.getElementById("strategySnippet"),
  overrideBox: document.getElementById("overrideBox"),
  warningsBox: document.getElementById("warningsBox"),
};

/* ===============================
   VERSION UTILS
================================ */
const Version = {
  normalize(v) {
    return v.replace(/[^0-9.]/g, "").split(".").map(n => +n || 0);
  },
  greaterThan(a, b) {
    const A = this.normalize(a);
    const B = this.normalize(b);
    for (let i = 0; i < Math.max(A.length, B.length); i++) {
      if ((A[i] || 0) > (B[i] || 0)) return true;
      if ((A[i] || 0) < (B[i] || 0)) return false;
    }
    return false;
  }
};

/* ===============================
   PARSERS
================================ */
const PomParser = {
  getJavaVersion(pom) {
    return +(pom.match(/<java.version>(.*?)<\/java.version>/)?.[1] || 8);
  },
  detectStack(pom, tree) {
    const content = pom + tree;
    if (/liberty|websphere/i.test(content)) return "LIBERTY";
    if (/spring/i.test(content)) return "SPRING";
    return "GENERIC";
  },
  extractExistingDependencyManagement(pom) {
    const match = pom.match(/<dependencyManagement>[\s\S]*?<\/dependencyManagement>/);
    return match ? match[0] : null;
  },
  parseDependencyManagement(xml) {
    const map = new Map();
    if (!xml) return map;

    const regex =
      /<dependency>[\s\S]*?<groupId>(.*?)<\/groupId>[\s\S]*?<artifactId>(.*?)<\/artifactId>[\s\S]*?<version>(.*?)<\/version>/g;
    let m;
    while ((m = regex.exec(xml))) {
      map.set(`${m[1]}:${m[2]}`, m[3]);
    }
    return map;
  }
};

const TreeParser = {
  parseParents(tree) {
    const lines = tree.split("\n").filter(l => l.includes("+-") || l.includes("\\-"));
    const stack = [];
    const map = new Map();

    lines.forEach(line => {
      const depth = (line.match(/\|/g) || []).length;
      const match = line.match(/ ([\w.-]+):([\w.-]+):/);
      if (!match) return;

      const ga = `${match[1]}:${match[2]}`;
      stack[depth] = ga;
      stack.length = depth + 1;

      if (depth > 0) {
        const parent = stack[depth - 1];
        if (!map.has(ga)) map.set(ga, new Set());
        map.get(ga).add(parent);
      }
    });

    return map;
  }
};

const MendParser = {
  extractFixes(mendJson) {
    const fixes = new Map();
    const regex = /([\w.-]+):([\w.-]+):([0-9][\w.-]*)/g;

    mendJson.libraries?.forEach(lib =>
      lib.vulnerabilities?.forEach(vuln => {
        let match;
        while ((match = regex.exec(vuln.topFix?.fixResolution || ""))) {
          const ga = `${match[1]}:${match[2]}`;
          const version = match[3].split(",")[0];
          if (!fixes.has(ga) || Version.greaterThan(version, fixes.get(ga))) {
            fixes.set(ga, version);
          }
        }
      })
    );

    return fixes;
  }
};

/* ===============================
   DEPENDENCY MANAGEMENT
================================ */
function buildDependencyManagement(dmMap) {
  let xml = `<dependencyManagement>\n  <dependencies>\n`;
  dmMap.forEach((version, ga) => {
    const [g, a] = ga.split(":");
    xml +=
      `    <dependency>\n` +
      `      <groupId>${g}</groupId>\n` +
      `      <artifactId>${a}</artifactId>\n` +
      `      <version>${version}</version>\n` +
      `    </dependency>\n`;
  });
  xml += `  </dependencies>\n</dependencyManagement>`;
  return xml;
}

function stripVersionsFromDependencies(pom, managedGAs) {
  return pom.replace(
    /<dependency>([\s\S]*?)<\/dependency>/g,
    block => {
      const g = block.match(/<groupId>(.*?)<\/groupId>/)?.[1];
      const a = block.match(/<artifactId>(.*?)<\/artifactId>/)?.[1];
      if (!g || !a) return block;

      const ga = `${g}:${a}`;
      if (!managedGAs.has(ga)) return block;

      return block.replace(/<version>[\s\S]*?<\/version>\s*/, "");
    }
  );
}

/* ===============================
   RULES
================================ */
function applyJavaConstraints(ga, version, java, warnings) {
  if (ga.startsWith("org.springframework") && java < 17 && Version.greaterThan(version, "5.3.39")) {
    warnings.push(
      `${ga}\n- Recomendado: ${version}\n- Aplicado: 5.3.39\n- Motivo: Spring 6 requer Java 17+`
    );
    return "5.3.39";
  }

  if (ga.startsWith("ch.qos.logback") && java < 11 && Version.greaterThan(version, "1.2.13")) {
    warnings.push(
      `${ga}\n- Recomendado: ${version}\n- Aplicado: 1.2.13\n- Motivo: Logback >= 1.3 requer Java 11+`
    );
    return "1.2.13";
  }

  return version;
}

/* ===============================
   MAIN
================================ */
function generatePom() {
  const pom = dom.pomInput.value;
  const tree = dom.treeInput.value;
  const mend = JSON.parse(dom.mendInput.value);
  const useExclude = dom.useExclude.checked;

  const java = PomParser.getJavaVersion(pom);
  const stack = PomParser.detectStack(pom, tree);

  const parents = TreeParser.parseParents(tree);
  const fixes = MendParser.extractFixes(mend);

  const warnings = [];
  const dmMap = PomParser.parseDependencyManagement(
    PomParser.extractExistingDependencyManagement(pom)
  );

  const direct = new Map();
  const excludes = new Map();

  fixes.forEach((version, ga) => {
    const applied = applyJavaConstraints(ga, version, java, warnings);
    dmMap.set(ga, applied);

    if (useExclude) {
      direct.set(ga, applied);
      parents.get(ga)?.forEach(parent => {
        if (!excludes.has(parent)) excludes.set(parent, new Set());
        excludes.get(parent).add(ga);
      });
    }
  });

  const dmXml = buildDependencyManagement(dmMap);
  const managedGAs = new Set(dmMap.keys());

  const cleanedPom = stripVersionsFromDependencies(pom, managedGAs);

  dom.pomOutput.value = cleanedPom
    .replace(/<dependencyManagement>[\s\S]*?<\/dependencyManagement>/, "")
    .replace("</project>", `\n${dmXml}\n</project>`);

  /* UI */
  dom.strategyBox.style.display = "flex";
  dom.strategyText.textContent = `Stack detectado: ${stack}\nJava: ${java}`;

  /* Overrides */
  if (useExclude) {
    let o = "";
    direct.forEach((version, ga) => {
      const [g, a] = ga.split(":");
      o += `<!-- Override para ${ga} -->\n\n`;

      parents.get(ga)?.forEach(parent => {
        const [pg, pa] = parent.split(":");
        o +=
          `<dependency>\n` +
          `  <groupId>${pg}</groupId>\n` +
          `  <artifactId>${pa}</artifactId>\n` +
          `  <exclusions>\n` +
          `    <exclusion>\n` +
          `      <groupId>${g}</groupId>\n` +
          `      <artifactId>${a}</artifactId>\n` +
          `    </exclusion>\n` +
          `  </exclusions>\n` +
          `</dependency>\n\n`;
      });

      o +=
        `<dependency>\n` +
        `  <groupId>${g}</groupId>\n` +
        `  <artifactId>${a}</artifactId>\n` +
        `  <version>${version}</version>\n` +
        `</dependency>\n\n`;
    });

    dom.overrideBox.style.display = "flex";
    dom.overrideOutput.value = o;
  } else {
    dom.overrideBox.style.display = "none";
  }

  dom.warningsBox.style.display = warnings.length ? "flex" : "none";
  dom.warningsArea.value = warnings.join("\n\n");
}

/* ===============================
   EVENTS
================================ */
dom.generateBtn.addEventListener("click", generatePom);
