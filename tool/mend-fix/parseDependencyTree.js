function parse(treeText) {
  const lines = treeText.split("\n").filter(l => l.includes("+-") || l.includes("\\-"));
  const nodes = [];

  for (const line of lines) {
    const depth = line.indexOf("+-") !== -1
      ? line.indexOf("+-") / 3
      : line.indexOf("\\-") / 3;

    const coords = line.replace(/.*[+-] /, "").split(":");
    if (coords.length < 4) continue;

    nodes.push({
      depth,
      groupId: coords[0],
      artifactId: coords[1],
      version: coords[3]
    });
  }

  return nodes;
}

module.exports = parse;
