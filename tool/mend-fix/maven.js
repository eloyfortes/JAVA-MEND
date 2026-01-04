// tools/auto-remediate/maven.js
const { execSync } = require("child_process");
const path = require("path");

const PROJECT_ROOT = path.resolve(__dirname, "../../");

function run(cmd) {
  return execSync(cmd, {
    cwd: PROJECT_ROOT,
    encoding: "utf8",
    stdio: "pipe"
  });
}

function dependencyTree() {
  return run("mvn -q dependency:tree");
}

function testBuild() {
  return run("mvn -q test");
}

module.exports = { dependencyTree, testBuild };
