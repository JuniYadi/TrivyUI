import spec from "../public/openapi.json" assert { type: "json" };
const anySpec: any = spec;
for (const [path, methods] of Object.entries(anySpec.paths)) {
  for (const [method, operation] of Object.entries(methods)) {
    const codes = Object.keys((operation as any).responses ?? {});
    const hasErr = codes.some((c: string) => c.startsWith("4") || c.startsWith("5"));
    if (!hasErr) console.log(method.toUpperCase(), path, "→", codes.join(", ") || "none");
  }
}
