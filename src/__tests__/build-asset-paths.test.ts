import { expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

test("package.json build script passes --public-path=/", async () => {
  const pkg = JSON.parse(await readFile(new URL("../../package.json", import.meta.url), "utf8"));
  expect(pkg.scripts.build).toContain("--public-path=/");
});

test("built index.html references assets with root-absolute URLs", async () => {
  // main.tsx imports the gitignored Tailwind output; generate it like `bun run build` does.
  const generatedCss = new URL("../styles/tailwind.generated.css", import.meta.url).pathname;
  if (!existsSync(generatedCss)) {
    const tw = Bun.spawnSync(["bun", "run", "tw:build"], { cwd: new URL("../..", import.meta.url).pathname });
    expect(tw.exitCode).toBe(0);
  }

  const outdir = await mkdtemp(join(tmpdir(), "trivyui-build-"));
  try {
    const result = await Bun.build({
      entrypoints: [new URL("../index.html", import.meta.url).pathname],
      outdir,
      publicPath: "/",
      target: "browser",
    });
    expect(result.success).toBe(true);

    const html = await readFile(join(outdir, "index.html"), "utf8");
    expect(html).not.toMatch(/(?:src|href)="\.\//);
    expect(html).toMatch(/src="\/[^"./][^"]*\.js"/);
    expect(html).toMatch(/href="\/[^"./][^"]*\.css"/);
  } finally {
    await rm(outdir, { recursive: true, force: true });
  }
});
