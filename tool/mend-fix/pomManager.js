// tools/auto-remediate/pomManager.js
const fs = require("fs");
const xml2js = require("xml2js");

async function loadPom() {
  const xml = fs.readFileSync("../../pom.xml", "utf8");
  return xml2js.parseStringPromise(xml);
}

function savePom(pom) {
  const builder = new xml2js.Builder();
  fs.writeFileSync("../../pom.xml", builder.buildObject(pom));
}

function ensureDependencyManagement(pom) {
  pom.project.dependencyManagement ??= [{}];
  pom.project.dependencyManagement[0].dependencies ??= [{}];
  pom.project.dependencyManagement[0].dependencies[0].dependency ??= [];
  return pom.project.dependencyManagement[0].dependencies[0].dependency;
}

function applyDependencyManagement(pom, fix) {
  const deps = ensureDependencyManagement(pom);
  const key = `${fix.groupId}:${fix.artifactId}`;

  if (deps.some(d =>
    `${d.groupId[0]}:${d.artifactId[0]}` === key
  )) return false;

  deps.push({
    groupId: [fix.groupId],
    artifactId: [fix.artifactId],
    version: [fix.version]
  });

  return true;
}

function applyExclude(pom, parent, fix) {
  const deps = pom.project.dependencies?.[0]?.dependency || [];

  const target = deps.find(d =>
    d.groupId[0] === parent.groupId &&
    d.artifactId[0] === parent.artifactId
  );

  if (!target) return;

  target.exclusions ??= [{}];
  target.exclusions[0].exclusion ??= [];

  target.exclusions[0].exclusion.push({
    groupId: [fix.groupId],
    artifactId: [fix.artifactId]
  });

  deps.push({
    groupId: [fix.groupId],
    artifactId: [fix.artifactId],
    version: [fix.version]
  });
}

module.exports = {
  loadPom,
  savePom,
  applyDependencyManagement,
  applyExclude
};
