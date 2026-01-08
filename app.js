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
   UTIL
================================ */
const Version = {
  normalize: v => v.replace(/[^0-9.]/g, "").split(".").map(n => +n || 0),

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

  parseDependencyManagement(xml) {
    const map = new Map();
    const regex = /<dependency>[\s\S]*?<groupId>(.*?)<\/groupId>[\s\S]*?<artifactId>(.*?)<\/artifactId>[\s\S]*?<version>(.*?)<\/version>/g;
    let match;
    while ((match = regex.exec(xml))) {
      map.set(`${match[1]}:${match[2]}`, match[3]);
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
   SERVICES
================================ */
const DependencyService = {
  applyJavaConstraints(ga, version, java, warnings) {
    if (ga.startsWith("org.springframework") && java < 17 && Version.greaterThan(version, "5.3.39")) {
      warnings.push(`${ga}\n- Aplicado: 5.3.39\n- Motivo: Spring 6 requer Java 17+`);
      return "5.3.39";
    }

    if (ga.startsWith("ch.qos.logback") && java < 11 && Version.greaterThan(version, "1.2.13")) {
      warnings.push(`${ga}\n- Aplicado: 1.2.13\n- Motivo: Logback >= 1.3 requer Java 11+`);
      return "1.2.13";
    }

    return version;
  }
};

/* ===============================
   MAIN FLOW
================================ */
function generatePom() {
  const pom = dom.pomInput.value;
  const tree = dom.treeInput.value;
  const mend = JSON.parse(dom.mendInput.value);

  const java = PomParser.getJavaVersion(pom);
  const stack = PomParser.detectStack(pom, tree);

  const fixes = MendParser.extractFixes(mend);
  const parents = TreeParser.parseParents(tree);

  const warnings = [];
  const dmMap = new Map();

  fixes.forEach((version, ga) => {
    const applied = DependencyService.applyJavaConstraints(ga, version, java, warnings);
    dmMap.set(ga, applied);
  });

  dom.pomOutput.value = pom; 

  dom.strategyBox.style.display = "flex";
  dom.strategyText.textContent = `Stack: ${stack}\nJava: ${java}`;

  dom.warningsBox.style.display = warnings.length ? "flex" : "none";
  dom.warningsArea.value = warnings.join("\n\n");
}

/* ===============================
   EVENTS
================================ */
dom.generateBtn.addEventListener("click", generatePom);
