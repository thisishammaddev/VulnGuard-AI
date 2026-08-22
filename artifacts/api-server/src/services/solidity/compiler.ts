import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import solc from "solc";

const require = createRequire(import.meta.url);
const openZeppelinRoot = path.dirname(require.resolve("@openzeppelin/contracts/package.json"));
const openZeppelinPrefix = "@openzeppelin/contracts/";

export type SolidityDiagnostic = {
  severity: "error" | "warning";
  message: string;
  formattedMessage: string;
  sourceLocation?: { start: number; end: number; file: string };
};

export type SolidityCompileResult = {
  success: boolean;
  diagnostics: SolidityDiagnostic[];
  compilerVersion: string;
  astAvailable: boolean;
};

type SolcOutput = {
  errors?: Array<{
    severity: "error" | "warning";
    message: string;
    formattedMessage: string;
    sourceLocation?: { start: number; end: number; file: string };
  }>;
  sources?: Record<string, { ast?: unknown }>;
};

function findImport(importPath: string): { contents?: string; error?: string } {
  if (!importPath.startsWith(openZeppelinPrefix)) {
    return { error: `Only ${openZeppelinPrefix} imports are supported.` };
  }

  const relativePath = importPath.slice(openZeppelinPrefix.length);
  const resolvedPath = path.resolve(openZeppelinRoot, relativePath);
  const rootWithSeparator = `${openZeppelinRoot}${path.sep}`;
  if (!resolvedPath.startsWith(rootWithSeparator) || !resolvedPath.endsWith(".sol")) {
    return { error: "Unsupported Solidity import path." };
  }

  try {
    return { contents: readFileSync(resolvedPath, "utf8") };
  } catch {
    return { error: `OpenZeppelin import not found: ${importPath}` };
  }
}

export function compileSolidity(source: string): SolidityCompileResult {
  const input = {
    language: "Solidity",
    sources: {
      "Contract.sol": { content: source },
    },
    settings: {
      optimizer: { enabled: false, runs: 200 },
      outputSelection: {
        "*": {
          "": ["ast"],
        },
      },
    },
  };

  const output = JSON.parse(solc.compile(JSON.stringify(input), { import: findImport })) as SolcOutput;
  const diagnostics = (output.errors ?? []).map((diagnostic) => ({
    severity: diagnostic.severity,
    message: diagnostic.message,
    formattedMessage: diagnostic.formattedMessage,
    sourceLocation: diagnostic.sourceLocation,
  }));

  return {
    success: !diagnostics.some((diagnostic) => diagnostic.severity === "error"),
    diagnostics,
    compilerVersion: solc.version(),
    astAvailable: Boolean(output.sources?.["Contract.sol"]?.ast),
  };
}