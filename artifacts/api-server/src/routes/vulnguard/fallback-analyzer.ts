type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export type FallbackVulnerability = {
  id: number;
  type: string;
  severity: Severity;
  swc_id: string | null;
  line_number: number | null;
  affected_lines: string | null;
  affected_functions: string | null;
  title: string;
  description: string;
  technical_risk: string;
  attack_scenario: string | null;
  impact: string | null;
  vulnerable_code: string | null;
  fixed_code: string | null;
  recommendation: string;
};

export type FallbackAnalysis = {
  vulnerabilities: FallbackVulnerability[];
  risk_score: number;
  summary: string;
};

function severityScore(sev: Severity): number {
  if (sev === "CRITICAL") return 35;
  if (sev === "HIGH") return 22;
  if (sev === "MEDIUM") return 12;
  return 6;
}

function calcRisk(vulnerabilities: FallbackVulnerability[]): number {
  if (vulnerabilities.length === 0) return 0;

  const score = vulnerabilities.reduce((sum, vuln) => sum + severityScore(vuln.severity), 0);
  return Math.min(98, Math.max(8, score));
}

function makeVulnerability(input: Omit<FallbackVulnerability, "id">, id: number): FallbackVulnerability {
  return {
    id,
    ...input,
  };
}

type FunctionBlock = {
  name: string;
  startLine: number;
  endLine: number;
  lines: string[];
};

function extractFunctionBlocks(code: string): FunctionBlock[] {
  const lines = code.split(/\r?\n/);
  const blocks: FunctionBlock[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const fnMatch = line.match(/\bfunction\s+([A-Za-z0-9_]+)\s*\(/);
    if (!fnMatch) continue;

    let braceDepth = 0;
    let started = false;
    let end = i;

    for (let j = i; j < lines.length; j++) {
      const current = lines[j];
      for (const ch of current) {
        if (ch === "{") {
          braceDepth++;
          started = true;
        }
        if (ch === "}") {
          braceDepth--;
        }
      }

      if (started && braceDepth <= 0) {
        end = j;
        break;
      }
    }

    blocks.push({
      name: fnMatch[1],
      startLine: i + 1,
      endLine: end + 1,
      lines: lines.slice(i, end + 1),
    });

    i = Math.max(i, end);
  }

  return blocks;
}

function firstLineMatching(lines: string[], regex: RegExp): number | null {
  for (let i = 0; i < lines.length; i++) {
    if (regex.test(lines[i])) return i;
  }
  return null;
}

function isStateMutationLine(line: string): boolean {
  const trimmed = line.trim();
  if (!trimmed) return false;

  // Skip control/guard lines that often include comparisons (>=, <=, ==, !=).
  if (/^(require|assert|if|while|for)\s*\(/.test(trimmed)) return false;

  // ++ / -- are clear mutation operations.
  if (/\+\+|--/.test(trimmed)) return true;

  // Match real assignment operators while avoiding comparison operators.
  // Examples matched: a = 1, x += 1, balances[msg.sender] -= amount
  const assignment = /(^|[^<>=!])([A-Za-z_][A-Za-z0-9_\.\[\]]*)\s*(\+=|-=|\*=|\/=|%=|=)/;
  if (!assignment.test(trimmed)) return false;

  // Avoid local variable declarations so we focus on state changes.
  if (/^(uint|int|address|bool|string|bytes\d*|bytes|mapping|struct|enum)\b/.test(trimmed)) {
    return false;
  }

  return true;
}

function firstMutationLine(lines: string[]): number | null {
  for (let i = 0; i < lines.length; i++) {
    if (isStateMutationLine(lines[i])) return i;
  }
  return null;
}

export function analyzeContractFallback(code: string, contractName?: string): FallbackAnalysis {
  const vulnerabilities: FallbackVulnerability[] = [];
  const sourceLines = code.split(/\r?\n/);
  const functions = extractFunctionBlocks(code);

  const push = (v: Omit<FallbackVulnerability, "id">) => {
    const duplicate = vulnerabilities.find(
      (x) => x.type === v.type && x.line_number === v.line_number,
    );
    if (!duplicate) vulnerabilities.push(makeVulnerability(v, vulnerabilities.length + 1));
  };

  // Check for security imports and patterns
  const hasReentrancyGuard = /ReentrancyGuard|nonReentrant/.test(code);
  const hasOpenZeppelin = /from\s+['"]\s*@openzeppelin\/contracts/.test(code);
  const hasSafeERC20 = /SafeERC20|safeTransfer|safeTransferFrom/.test(code);
  const isSolidity0_8Plus = /pragma\s+solidity\s+\^0\.8|pragma\s+solidity\s+>=0\.8/.test(code);

  // ════════════════════════════════════════════════════════════════════════════
  // 1. REENTRANCY - Only flag if external call + state mutation without guard
  // ════════════════════════════════════════════════════════════════════════════
  for (const fn of functions) {
    const hasNonReentrantModifier = /nonReentrant/.test(fn.lines[0]);
    if (hasNonReentrantModifier) continue; // Skip if protected
    
    const extRegex = /(\.call\s*\{|\.call\s*\(|\.send\s*\(|\.transfer\s*\()/;
    const extIdx = firstLineMatching(fn.lines, extRegex);
    const updateIdx = firstMutationLine(fn.lines);

    if (extIdx !== null && updateIdx !== null && extIdx < updateIdx && !hasReentrancyGuard) {
      const line = fn.startLine + extIdx;
      push({
        type: "reentrancy",
        severity: "CRITICAL",
        swc_id: "SWC-107",
        line_number: line,
        affected_lines: `line ${line}`,
        affected_functions: fn.name,
        title: `Potential reentrancy in ${fn.name}()`,
        description: "External call appears before state update without reentrancy protection.",
        technical_risk: "Attacker contract can re-enter before state is updated.",
        attack_scenario: "Attacker re-enters function before balance is deducted and drains funds.",
        impact: "Loss of contract funds.",
        vulnerable_code: sourceLines[line - 1]?.trim() ?? null,
        fixed_code: null,
        recommendation: "Use nonReentrant modifier from OpenZeppelin ReentrancyGuard.",
      });
    }

    // Verifying low-level call results requires parsing full control flow.
    // The regex fallback deliberately does not emit SWC-104 findings.
  }

  // ════════════════════════════════════════════════════════════════════════════
  // 2. TX.ORIGIN USAGE IN AUTHORIZATION - Real issue, always flag
  // ════════════════════════════════════════════════════════════════════════════
  sourceLines.forEach((line, i) => {
    if (/\btx\.origin\s*==|auth.*tx\.origin|require.*tx\.origin/.test(line)) {
      const lineNo = i + 1;
      push({
        type: "tx-origin-auth",
        severity: "HIGH",
        swc_id: "SWC-115",
        line_number: lineNo,
        affected_lines: `line ${lineNo}`,
        affected_functions: null,
        title: "tx.origin used for authorization",
        description: "tx.origin is used for access control.",
        technical_risk: "Can be bypassed with phishing proxy contracts.",
        attack_scenario: "Attacker contract calls victim function, tx.origin is original user.",
        impact: "Unauthorized function execution.",
        vulnerable_code: line.trim(),
        fixed_code: null,
        recommendation: "Use msg.sender instead of tx.origin.",
      });
    }
  });

  // ════════════════════════════════════════════════════════════════════════════
  // 3. DELEGATECALL USAGE - Only flag if target is not validated/hardcoded
  // ════════════════════════════════════════════════════════════════════════════
  sourceLines.forEach((line, i) => {
    if (/\bdelegatecall\s*\(/.test(line)) {
      // Check if next line or surrounding code validates the target
      const context = sourceLines.slice(Math.max(0, i - 2), Math.min(sourceLines.length, i + 3)).join("\n");
      const hasValidation = /require|assert|address\(0\)/.test(context);
      const isHardcoded = /delegatecall\s*\(\s*"0x[0-9a-fA-F]{40}"/.test(line);
      
      if (!hasValidation && !isHardcoded) {
        const lineNo = i + 1;
        push({
          type: "delegatecall-risk",
          severity: "CRITICAL",
          swc_id: "SWC-112",
          line_number: lineNo,
          affected_lines: `line ${lineNo}`,
          affected_functions: null,
          title: "Unsafe delegatecall detected",
          description: "delegatecall to unvalidated target without address verification.",
          technical_risk: "Uncontrolled implementation can steal contract storage/funds.",
          attack_scenario: "Attacker provides malicious implementation address.",
          impact: "Complete contract compromise.",
          vulnerable_code: line.trim(),
          fixed_code: null,
          recommendation: "Validate delegatecall target with require(). Use established proxy patterns.",
        });
      }
    }
  });

  // ════════════════════════════════════════════════════════════════════════════
  // 4. WEAK RANDOMNESS - Only flag active randomness usage, not just presence
  // ════════════════════════════════════════════════════════════════════════════
  sourceLines.forEach((line, i) => {
    // Only flag if block.timestamp/number is used in actual randomness generation
    if (/\b(block\.timestamp|blockhash|block\.number)\s*[+\-*%]|uint.*%\s*(block\.(timestamp|number))|\bhash\s*\(.*block\.(timestamp|number)/.test(line)) {
      const lineNo = i + 1;
      push({
        type: "weak-randomness",
        severity: "MEDIUM",
        swc_id: "SWC-120",
        line_number: lineNo,
        affected_lines: `line ${lineNo}`,
        affected_functions: null,
        title: "Weak randomness source",
        description: "Block values used for randomness are predictable.",
        technical_risk: "Miners can bias randomness outcome.",
        attack_scenario: "Attacker influences block properties for favorable randomness.",
        impact: "Biased random outcomes in games/lotteries.",
        vulnerable_code: line.trim(),
        fixed_code: null,
        recommendation: "Use Chainlink VRF or other oracle for true randomness.",
      });
    }
  });

  // ════════════════════════════════════════════════════════════════════════════
  // 5. UNCHECKED MATH - Only flag Solidity < 0.8 without SafeMath
  // ════════════════════════════════════════════════════════════════════════════
  if (!isSolidity0_8Plus) {
    sourceLines.forEach((line, i) => {
      if (/\b(balances|amounts|totals|supply|total)\[.*\]\s*[+\-]\s*=|=\s*.*\b(balances|amounts)\[.*\]\s*[+\-]/.test(line)) {
        if (!line.includes("SafeMath") && !line.includes(".add(") && !line.includes(".sub(")) {
          const lineNo = i + 1;
          push({
            type: "unchecked-math",
            severity: "HIGH",
            swc_id: "SWC-101",
            line_number: lineNo,
            affected_lines: `line ${lineNo}`,
            affected_functions: null,
            title: "Unchecked math operation (Solidity < 0.8)",
            description: "Arithmetic on state without SafeMath.",
            technical_risk: "Integer overflow/underflow possible.",
            attack_scenario: "Attacker overflows balance to gain infinite tokens.",
            impact: "Infinite minting or fund loss.",
            vulnerable_code: line.trim(),
            fixed_code: null,
            recommendation: "Use SafeMath library or upgrade to Solidity 0.8+.",
          });
        }
      }
    });
  }

  // ════════════════════════════════════════════════════════════════════════════
  // 6. DANGEROUS TIMESTAMP USAGE - Only flag equality checks
  // ════════════════════════════════════════════════════════════════════════════
  sourceLines.forEach((line, i) => {
    // Only flag strict equality with timestamp
    if (/\b(block\.timestamp|now)\s*==\s*|==\s*(block\.timestamp|now)\b/.test(line)) {
      const lineNo = i + 1;
      push({
        type: "timestamp-dependence",
        severity: "MEDIUM",
        swc_id: "SWC-116",
        line_number: lineNo,
        affected_lines: `line ${lineNo}`,
        affected_functions: null,
        title: "Timestamp equality check",
        description: "Strict equality with block.timestamp is easily manipulated.",
        technical_risk: "Miners can adjust timestamp within ~15 second range.",
        attack_scenario: "Attacker waits for favorable timestamp to match condition.",
        impact: "Logic bypass or transaction ordering manipulation.",
        vulnerable_code: line.trim(),
        fixed_code: null,
        recommendation: "Use >= or <= instead of ==. Consider block numbers for critical timing.",
      });
    }
  });

  // ════════════════════════════════════════════════════════════════════════════
  // 7. MISSING ACCESS CONTROL - Only flag truly public state-changing functions
  // ════════════════════════════════════════════════════════════════════════════
  for (const fn of functions) {
    const fnDecl = fn.lines[0];
    const isPublic = /\bpublic\b|\bexternal\b/.test(fnDecl);
    const isStateChanging = fn.lines.some((l) => isStateMutationLine(l));
    const hasRequire = fn.lines.some((l) => /\brequire\s*\(/.test(l));
    const hasModifier = /\b(onlyOwner|onlyRole|nonReentrant|onlyMinter|onlyBurner)\b/.test(fnDecl);
    
    if (isPublic && isStateChanging && !hasRequire && !hasModifier && !fn.name.startsWith("_")) {
      // Only flag if no require/modifier AND name suggests sensitive operation
      if (/withdraw|transfer|mint|burn|set|remove|destroy|kill|pause|unpause|admin|owner|approve/.test(fn.name)) {
        push({
          type: "missing-access-control",
          severity: "CRITICAL",
          swc_id: "SWC-105",
          line_number: fn.startLine,
          affected_lines: `lines ${fn.startLine}-${fn.endLine}`,
          affected_functions: fn.name,
          title: `Unrestricted ${fn.name}()`,
          description: "Public state-changing function with no access control.",
          technical_risk: "Anyone can call sensitive function.",
          attack_scenario: "Attacker calls withdraw(), mint(), or setOwner().",
          impact: "Fund theft or contract takeover.",
          vulnerable_code: fnDecl.trim(),
          fixed_code: null,
          recommendation: "Add require() or onlyOwner modifier.",
        });
      }
    }
  }

  // ════════════════════════════════════════════════════════════════════════════
  // 8. SELFDESTRUCT - Always critical if not properly guarded
  // ════════════════════════════════════════════════════════════════════════════
  sourceLines.forEach((line, i) => {
    if (/\bselfdestruct\s*\(|suicide\s*\(/.test(line)) {
      // Check if previous lines have require/modifier guard
      const context = sourceLines.slice(Math.max(0, i - 5), i + 1).join("\n");
      const hasGuard = /require|onlyOwner|onlyRole|msg\.sender|modifier/.test(context);
      
      const lineNo = i + 1;
      push({
        type: "selfdestruct-usage",
        severity: hasGuard ? "MEDIUM" : "CRITICAL",
        swc_id: "SWC-106",
        line_number: lineNo,
        affected_lines: `line ${lineNo}`,
        affected_functions: null,
        title: hasGuard ? "Protected selfdestruct" : "Unprotected selfdestruct",
        description: "Contract can be destroyed.",
        technical_risk: "Permanent loss of contract functionality.",
        attack_scenario: "Attacker calls selfdestruct and drains funds.",
        impact: "Contract destruction.",
        vulnerable_code: line.trim(),
        fixed_code: null,
        recommendation: "Restrict selfdestruct with require(msg.sender == owner). Consider pausing instead.",
      });
    }
  });

  // ════════════════════════════════════════════════════════════════════════════
  // 9. SWC-118 – INCORRECT CONSTRUCTOR NAME
  // ════════════════════════════════════════════════════════════════════════════
  const constructorMatch = code.match(/contract\s+([A-Za-z0-9_]+)\s*\{/);
  const contractNameFromCode = constructorMatch?.[1];
  if (contractNameFromCode) {
    sourceLines.forEach((line, i) => {
      if (/\b(function)\s+[A-Za-z0-9_]*\s*\(.*\)/.test(line)) {
        const fnNameMatch = line.match(/function\s+([A-Za-z0-9_]+)\s*\(/);
        if (fnNameMatch) {
          const fnName = fnNameMatch[1];
          // Old Solidity: constructor was named same as contract
          if (fnName === contractNameFromCode && !fnName.includes("constructor")) {
            const lineNo = i + 1;
            push({
              type: "incorrect-constructor",
              severity: "MEDIUM",
              swc_id: "SWC-118",
              line_number: lineNo,
              affected_lines: `line ${lineNo}`,
              affected_functions: fnName,
              title: `Incorrect constructor name: ${fnName}()`,
              description: "Function named after contract (old Solidity constructor syntax).",
              technical_risk: "Constructor may not execute, leading to uninitialized state.",
              attack_scenario: "If constructor doesn't run, contract state is uninitialized.",
              impact: "Uninitialized state variables, broken contract logic.",
              vulnerable_code: line.trim(),
              fixed_code: null,
              recommendation: "Use modern 'constructor()' keyword instead of contract name.",
            });
          }
        }
      }
    });
  }

  // ════════════════════════════════════════════════════════════════════════════
  // 10. SWC-113 – DOS WITH FAILED CALL
  // ════════════════════════════════════════════════════════════════════════════
  sourceLines.forEach((line, i) => {
    if (/\bfor\s*\(.*in|forEach|while\s*\(.*\.length|map\s*\(|filter\s*\(/.test(line) && /\.call|\.send|\.transfer/.test(sourceLines.slice(i, Math.min(i + 10, sourceLines.length)).join("\n"))) {
      // Check if there's a loop with external calls
      const context = sourceLines.slice(i, Math.min(i + 10, sourceLines.length)).join("\n");
      if (/\.call|\.send|\.transfer/.test(context) && !/try|catch|require/.test(context)) {
        const lineNo = i + 1;
        push({
          type: "dos-failed-call",
          severity: "HIGH",
          swc_id: "SWC-113",
          line_number: lineNo,
          affected_lines: `lines ${lineNo}-${Math.min(lineNo + 10, sourceLines.length)}`,
          affected_functions: null,
          title: "DoS with Failed Call in Loop",
          description: "Loop contains external calls without proper failure handling.",
          technical_risk: "Single failed call can revert entire transaction.",
          attack_scenario: "Attacker adds themselves to array, causes their transfer to fail, blocking entire operation.",
          impact: "Denial of service - function becomes unusable.",
          vulnerable_code: line.trim(),
          fixed_code: null,
          recommendation: "Use pull-payment pattern or isolate each call with try-catch.",
        });
      }
    }
  });

  // ════════════════════════════════════════════════════════════════════════════
  // 11. SWC-128 – DOS WITH BLOCK GAS LIMIT
  // ════════════════════════════════════════════════════════════════════════════
  sourceLines.forEach((line, i) => {
    if (/\bfor\s*\(|while\s*\(|forEach\s*\(/.test(line) && /\.length|\.size|count/.test(sourceLines.slice(Math.max(0, i - 2), i + 5).join("\n"))) {
      // Unbounded loop over dynamic array length
      const context = sourceLines.slice(i, Math.min(i + 15, sourceLines.length)).join("\n");
      if (/balances|users|tokens|holders|addresses/.test(context) && !/for\s*\(\s*uint\s+\w+\s*=\s*0\s*;\s*\w+\s*<\s*\d+/.test(context)) {
        const lineNo = i + 1;
        push({
          type: "dos-block-gas",
          severity: "MEDIUM",
          swc_id: "SWC-128",
          line_number: lineNo,
          affected_lines: `lines ${lineNo}-${Math.min(lineNo + 10, sourceLines.length)}`,
          affected_functions: null,
          title: "DoS with Block Gas Limit",
          description: "Unbounded loop over dynamic-sized data structure.",
          technical_risk: "As array grows, transaction will exceed gas limit and revert.",
          attack_scenario: "Attacker continuously adds entries, eventually blocking function execution.",
          impact: "Function becomes permanently unusable when array exceeds gas limit.",
          vulnerable_code: line.trim(),
          fixed_code: null,
          recommendation: "Limit loop iterations, use pagination, or external off-chain tracking.",
        });
      }
    }
  });

  // Signature validation, visibility, and shadowing require AST context.
  // This regex fallback intentionally does not emit findings for these categories.


  // ════════════════════════════════════════════════════════════════════════════
  // 18. SWC-111 – DEPRECATED SOLIDITY FUNCTIONS
  // ════════════════════════════════════════════════════════════════════════════
  const deprecatedFunctions = [
    { name: "sha3", replacement: "keccak256", swc: "SWC-111" },
    { name: "throw", replacement: "revert()", swc: "SWC-111" },
    { name: "suicide", replacement: "selfdestruct", swc: "SWC-111" },
    { name: "var ", replacement: "explicit type", swc: "SWC-111" },
    { name: "callcode", replacement: "delegatecall", swc: "SWC-111" },
  ];

  deprecatedFunctions.forEach((deprecated) => {
    sourceLines.forEach((line, i) => {
      if (new RegExp(`\\b${deprecated.name}\\b`).test(line)) {
        const lineNo = i + 1;
        push({
          type: "deprecated-function",
          severity: "LOW",
          swc_id: deprecated.swc,
          line_number: lineNo,
          affected_lines: `line ${lineNo}`,
          affected_functions: null,
          title: `Deprecated function: ${deprecated.name}()`,
          description: `${deprecated.name}() is deprecated in modern Solidity.`,
          technical_risk: "May cause unexpected behavior in newer compiler versions.",
          attack_scenario: "Code fails to compile with new Solidity versions.",
          impact: "Compatibility issues.",
          vulnerable_code: line.trim(),
          fixed_code: null,
          recommendation: `Replace with ${deprecated.replacement}.`,
        });
      }
    });
  });

  // ════════════════════════════════════════════════════════════════════════════
  // 19. SWC-137 – FLOATING PRAGMA
  // ════════════════════════════════════════════════════════════════════════════
  sourceLines.forEach((line, i) => {
    if (/pragma\s+solidity\s+[\^><=!]+/.test(line)) {
      // Floating pragma (not pinned to exact version)
      if (!/pragma\s+solidity\s+(0\.\d+\.\d+|>=\d+\.\d+\.\d+\s+<\d+\.\d+\.\d+)/.test(line)) {
        const lineNo = i + 1;
        push({
          type: "floating-pragma",
          severity: "LOW",
          swc_id: "SWC-137",
          line_number: lineNo,
          affected_lines: `line ${lineNo}`,
          affected_functions: null,
          title: "Floating Pragma",
          description: "Pragma uses caret/tilde allowing version range.",
          technical_risk: "Different compiler versions may produce different behavior.",
          attack_scenario: "Code compiled with different Solidity version behaves unexpectedly.",
          impact: "Inconsistent behavior across environments.",
          vulnerable_code: line.trim(),
          fixed_code: null,
          recommendation: "Pin pragma to exact version: pragma solidity 0.8.x;",
        });
      }
    }
  });

  // ════════════════════════════════════════════════════════════════════════════
  // 20. SWC-133 – HASH COLLISIONS WITH ABI.ENCODEPACKED
  // ════════════════════════════════════════════════════════════════════════════
  sourceLines.forEach((line, i) => {
    if (/abi\.encodePacked\s*\(/.test(line) && /keccak256|sha3/.test(sourceLines.slice(Math.max(0, i - 1), Math.min(i + 2, sourceLines.length)).join("\n"))) {
      const lineNo = i + 1;
      push({
        type: "hash-collision",
        severity: "MEDIUM",
        swc_id: "SWC-133",
        line_number: lineNo,
        affected_lines: `line ${lineNo}`,
        affected_functions: null,
        title: "Hash Collision Risk with abi.encodePacked",
        description: "abi.encodePacked can cause hash collisions.",
        technical_risk: "Different inputs can produce same hash.",
        attack_scenario: "Attacker crafts collision to bypass hash-based checks.",
        impact: "Access control bypass, state corruption.",
        vulnerable_code: line.trim(),
        fixed_code: null,
        recommendation: "Use abi.encode() instead of abi.encodePacked().",
      });
    }
  });

  // ════════════════════════════════════════════════════════════════════════════
  // 21. SWC-110 – ASSERT VIOLATION
  // ════════════════════════════════════════════════════════════════════════════
  sourceLines.forEach((line, i) => {
    if (/\bassert\s*\(/.test(line)) {
      const context = sourceLines.slice(Math.max(0, i - 2), Math.min(i + 3, sourceLines.length)).join("\n");
      if (!/condition|invariant|internal|private/.test(context)) {
        const lineNo = i + 1;
        push({
          type: "assert-violation",
          severity: "MEDIUM",
          swc_id: "SWC-110",
          line_number: lineNo,
          affected_lines: `line ${lineNo}`,
          affected_functions: null,
          title: "Assert Used for Input Validation",
          description: "assert() used instead of require() for validation.",
          technical_risk: "Assert consumes all gas on failure (bad for production).",
          attack_scenario: "Attacker triggers assert(), burning caller's gas.",
          impact: "DoS via gas exhaustion.",
          vulnerable_code: line.trim(),
          fixed_code: null,
          recommendation: "Use require() for input validation, assert() only for invariants.",
        });
      }
    }
  });

  // ════════════════════════════════════════════════════════════════════════════
  // Transaction-order dependence requires semantic data-flow analysis. The regex
  // fallback intentionally does not emit SWC-114 front-running findings.
  // 23. SWC-132 – UNEXPECTED ETHER BALANCE
  // ════════════════════════════════════════════════════════════════════════════
  sourceLines.forEach((line, i) => {
    if (/address\(this\)\.balance|this\.balance|balance\s*==|\.balance\s*>|\.balance\s*</.test(line)) {
      const context = sourceLines.slice(Math.max(0, i - 2), Math.min(i + 3, sourceLines.length)).join("\n");
      if (!/selfdestruct|receive|fallback/.test(context)) {
        const lineNo = i + 1;
        push({
          type: "unexpected-ether",
          severity: "MEDIUM",
          swc_id: "SWC-132",
          line_number: lineNo,
          affected_lines: `line ${lineNo}`,
          affected_functions: null,
          title: "Unexpected Ether Balance",
          description: "Code assumes specific Ether balance.",
          technical_risk: "External parties can send Ether, breaking assumptions.",
          attack_scenario: "Attacker sends Ether to contract, breaking logic.",
          impact: "Logic bypass, funds trapped or lost.",
          vulnerable_code: line.trim(),
          fixed_code: null,
          recommendation: "Track Ether internally, don't rely on balance() for tracking.",
        });
      }
    }
  });

  // ════════════════════════════════════════════════════════════════════════════
  // 24. SWC-136 – UNENCRYPTED PRIVATE DATA ON-CHAIN
  // ════════════════════════════════════════════════════════════════════════════
  sourceLines.forEach((line, i) => {
    if (/\bprivate\s+(uint|bytes|address|bool)\s+\w+|secret|password|key|private_key/.test(line)) {
      const lineNo = i + 1;
      push({
        type: "unencrypted-private",
        severity: "HIGH",
        swc_id: "SWC-136",
        line_number: lineNo,
        affected_lines: `line ${lineNo}`,
        affected_functions: null,
        title: "Unencrypted Private Data On-Chain",
        description: "Private state variables are readable from blockchain.",
        technical_risk: "All blockchain data is public and can be read.",
        attack_scenario: "Attacker reads contract storage to find secrets.",
        impact: "Exposure of sensitive data.",
        vulnerable_code: line.trim(),
        fixed_code: null,
        recommendation: "Never store secrets on-chain. Use commit-reveal or off-chain computation.",
      });
    }
  });

  // ════════════════════════════════════════════════════════════════════════════
  // 25. SWC-134 – MESSAGE CALL WITH HARDCODED GAS AMOUNT
  // ════════════════════════════════════════════════════════════════════════════
  sourceLines.forEach((line, i) => {
    if (/\.call\s*\{[^}]*gas\s*:\s*\d+/.test(line)) {
      const lineNo = i + 1;
      push({
        type: "hardcoded-gas",
        severity: "MEDIUM",
        swc_id: "SWC-134",
        line_number: lineNo,
        affected_lines: `line ${lineNo}`,
        affected_functions: null,
        title: "Hardcoded Gas Amount in Call",
        description: "External call with hardcoded gas value.",
        technical_risk: "Hardcoded gas can fail as gas costs change.",
        attack_scenario: "Gas costs increase in future EVM versions, calls fail.",
        impact: "Broken functionality in future versions.",
        vulnerable_code: line.trim(),
        fixed_code: null,
        recommendation: "Use dynamic gas (gasleft() - buffer) or remove gas limit.",
      });
    }
  });

  // ════════════════════════════════════════════════════════════════════════════
  // CALCULATE RISK SCORE
  // ════════════════════════════════════════════════════════════════════════════
  const risk_score = calcRisk(vulnerabilities);
  const targetName = contractName || "the contract";
  const issueCount = vulnerabilities.length;
  
  const criticalCount = vulnerabilities.filter((v) => v.severity === "CRITICAL").length;
  const highCount = vulnerabilities.filter((v) => v.severity === "HIGH").length;
  const mediumCount = vulnerabilities.filter((v) => v.severity === "MEDIUM").length;
  const lowCount = vulnerabilities.filter((v) => v.severity === "LOW").length;
  
  const summary = issueCount === 0
    ? `No vulnerabilities detected in ${targetName}. Code appears secure.`
    : `Static analysis detected ${issueCount} issue(s): ${criticalCount} critical, ${highCount} high, ${mediumCount} medium, ${lowCount} low.`;

  return {
    vulnerabilities,
    risk_score,
    summary,
  };
}
