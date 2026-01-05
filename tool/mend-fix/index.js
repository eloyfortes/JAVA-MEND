// tools/auto-remediate/index.js
const parseVulnReport = require("./parseVulnReport");
const parseTree = require("./parseDependencyTree");
const maven = require("./maven");
const pomMgr = require("./pomManager");

(async () => {
  const fixes = parseVulnReport("../../report.json");
  let pom = await pomMgr.loadPom();

  const originalTree = parseTree(maven.dependencyTree());

  for (const fix of fixes) {
    console.log(`Tentando DM: ${fix.key}`);

    pomMgr.applyDependencyManagement(pom, fix);
    pomMgr.savePom(pom);

    const newTree = parseTree(maven.dependencyTree());
    const resolved = newTree.some(n =>
      n.groupId === fix.groupId &&
      n.artifactId === fix.artifactId &&
      n.version === fix.version
    );

    if (resolved) {
      console.log(` Resolvido via dependencyManagement`);
      continue;
    }

    console.log(`DM falhou → tentando exclude`);

    const parent = originalTree.find(n =>
      n.depth >= 0 &&
      originalTree.some(c =>
        c.depth === n.depth + 1 &&
        c.groupId === fix.groupId &&
        c.artifactId === fix.artifactId
      )
    );

    if (!parent) {
      console.log(`❌ Não foi possível excluir automaticamente`);
      continue;
    }

    pomMgr.applyExclude(pom, parent, fix);
    pomMgr.savePom(pom);
  }

  console.log("Rodando build final...");
  maven.testBuild();

  console.log("✔ Auto-remediação concluída");
})();
