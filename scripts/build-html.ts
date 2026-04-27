const sourcePath = "src/index.html";
const outputPath = "dist/index.html";

const source = await Bun.file(sourcePath).text();

const withStyle = source.includes('href="./main.css"')
  ? source
  : source.replace("</head>", '    <link rel="stylesheet" href="./main.css" />\n  </head>');

const normalized = withStyle.replace(
  /<script\s+type="module"\s+src="\.\/main\.tsx"><\/script>/,
  '<script type="module" src="./main.js"></script>'
);

await Bun.write(outputPath, normalized);
console.log(`Wrote ${outputPath}`);
