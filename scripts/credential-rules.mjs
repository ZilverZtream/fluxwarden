import { dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

const repositoryRoot = dirname(dirname(fileURLToPath(import.meta.url)));

// Types whose values are bytes.
const BINARY = new Set(['Buffer', 'Uint8Array', 'Uint8ClampedArray', 'Int8Array', 'Uint16Array', 'Int16Array', 'Uint32Array',
  'Int32Array', 'Float32Array', 'Float64Array', 'BigInt64Array', 'BigUint64Array', 'ArrayBuffer', 'SharedArrayBuffer',
  'ArrayBufferLike', 'ArrayBufferView', 'DataView']);

/**
 * Whether a value of this type can carry credential text or bytes: a string or binary
 * type, an opaque any/unknown, or a function, class, object, array or generic whose
 * results, members or type arguments can. Library types are judged by their type
 * arguments only (a Date's toString is not a credential).
 */
function carriesData(checker, program, type, seen = new Set(), depth = 0) {
  if (depth > 8 || seen.has(type)) return false;
  seen.add(type);
  const flags = ts.TypeFlags;
  if (type.flags & (flags.String | flags.StringLiteral | flags.TemplateLiteral | flags.StringMapping | flags.Any | flags.Unknown)) return true;
  const inner = (next) => carriesData(checker, program, next, seen, depth + 1);
  if (type.isUnionOrIntersection()) return type.types.some(inner);
  const symbol = type.aliasSymbol ?? type.getSymbol();
  if (symbol && BINARY.has(symbol.getName())) return true;
  for (const signature of [...type.getCallSignatures(), ...type.getConstructSignatures()]) {
    if (inner(signature.getReturnType())) return true;
    if (signature.getParameters().some(parameter => handsOut(checker, checker.getTypeOfSymbol(parameter), inner))) return true;
  }
  if (!(type.flags & flags.Object)) return false;
  if (type.objectFlags & ts.ObjectFlags.Reference && checker.getTypeArguments(type).some(inner)) return true;
  if (type.aliasTypeArguments?.some(inner)) return true;
  const library = symbol?.declarations?.some(declaration => {
    const file = declaration.getSourceFile();
    return program.isSourceFileDefaultLibrary(file) || program.isSourceFileFromExternalLibrary(file) || /[\\/]node_modules[\\/]/.test(file.fileName);
  });
  if (library) return false;
  for (const property of checker.getPropertiesOfType(type)) {
    const declaration = property.valueDeclaration ?? property.declarations?.[0];
    if (declaration && inner(checker.getTypeOfSymbolAtLocation(property, declaration))) return true;
  }
  return false;
}

/**
 * Whether a parameter of this type lets a function hand data to its caller: a callback (or a
 * method of a caller-supplied object) that takes text or bytes, or a writable property of a
 * caller-supplied object that can hold them.
 */
function handsOut(checker, parameterType, carries) {
  const parts = parameterType.isUnion() ? parameterType.types : [parameterType];
  return parts.some(part => {
    const plain = (part.getSymbol()?.flags ?? 0) & (ts.SymbolFlags.Interface | ts.SymbolFlags.TypeLiteral | ts.SymbolFlags.ObjectLiteral);
    const properties = plain ? checker.getPropertiesOfType(part) : [];
    const writable = property => (property.declarations ?? []).some(item =>
      ts.isPropertySignature(item) && !(ts.getCombinedModifierFlags(item) & ts.ModifierFlags.Readonly));
    if (properties.some(property => writable(property) && carries(checker.getTypeOfSymbol(property)))) return true;
    const members = part.getCallSignatures().length > 0 ? [part] : properties.map(property => checker.getTypeOfSymbol(property));
    return members.some(member => member.getCallSignatures().some(callback =>
      callback.getParameters().some(argument => carries(checker.getTypeOfSymbol(argument)))));
  });
}

/** A function that takes a Secret and returns bytes is the reveal capability itself. */
function capabilityShaped(checker, type) {
  return type.getCallSignatures().some(signature => signature.getParameters().some(parameter => {
    const declaration = parameter.valueDeclaration;
    return declaration && /\bSecret\b/.test(checker.typeToString(checker.getTypeOfSymbolAtLocation(parameter, declaration)));
  }) && /\b(?:Uint8Array|Buffer|ArrayBuffer)\b/.test(checker.typeToString(signature.getReturnType())));
}

/**
 * Type-aware check of an allowed reveal module: every value it exports, under any name
 * and however re-exported, is judged by its TypeScript type. Exporting the capability is
 * always an error. An export whose implementation reaches the capability (directly or
 * through other declarations of the module) and that can carry text or bytes needs an
 * allow-list entry; in the signer, which holds the operator key, every such export does.
 * Exports of an adapter that never reach the capability (aliases, pubkeys, parsed node
 * data) are not restricted.
 */
function typedExports(context, file, program, touches, strict) {
  const services = context.sourceCode.parserServices;
  const tsProgram = services?.program;
  if (!tsProgram || !program) return;
  const checker = tsProgram.getTypeChecker();
  const source = services.esTreeNodeToTSNodeMap.get(program);
  const module = source && checker.getSymbolAtLocation(source);
  if (!module) return;
  const allowed = new Set((context.options[0]?.allow ?? []).map(entry => `${entry.file}#${entry.export}`));
  for (const exported of checker.getExportsOfModule(module)) {
    const name = exported.getName();
    const target = exported.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(exported) : exported;
    if (!(target.flags & ts.SymbolFlags.Value)) continue;
    const declaration = target.valueDeclaration ?? target.declarations?.[0];
    const local = exported.declarations?.find(item => item.getSourceFile() === source) ?? declaration;
    const node = (local && services.tsNodeToESTreeNodeMap.get(local)) ?? program;
    if (!declaration) continue;
    const type = checker.getTypeOfSymbolAtLocation(target, declaration);
    const revealed = /(?:^|[\\/])secret\.[cm]?[jt]s$/.test(declaration.getSourceFile().fileName) && target.getName() === 'revealSecret';
    if (revealed || capabilityShaped(checker, type)) context.report({ node, messageId: 'capabilityExport', data: { name } });
    else if (allowed.has(`${file}#${name}`)) continue;
    else if (!strict && !touches(services.tsNodeToESTreeNodeMap.get(declaration))) continue;
    else if (carriesData(checker, tsProgram, type)) context.report({ node, messageId: 'dataExport', data: { name } });
  }
}

export const credentialCapability = {
  meta: {
    type: 'problem',
    schema: [{
      type: 'object', additionalProperties: false,
      properties: {
        allow: {
          type: 'array',
          items: {
            type: 'object', additionalProperties: false, required: ['file', 'export', 'reason'],
            properties: { file: { type: 'string' }, export: { type: 'string' }, reason: { type: 'string', pattern: '\\S' } },
          },
        },
      },
    }],
    messages: {
      forbidden: 'Credential reveal capability is confined to node adapters and approval signing.',
      capabilityExport: 'A credential module must not export the reveal capability in any form ({{name}}).',
      dataExport: 'Export {{name}} of a credential module carries text or bytes; list it with a reason in the credential export allow-list.',
    },
  },
  create(context) {
    // Locations are decided on the path inside the repository, never on parent directories.
    const filename = `/${relative(repositoryRoot, context.filename).replace(/\\/g, '/')}`;
    const names = new Set(['reveal', 'revealSecret']);
    const report = node => context.report({ node, messageId: 'forbidden' });
    const secretModule = value => typeof value === 'string' && /(?:^|\/)secret(?:\.js|\.ts)?(?:[?#][\s\S]*)?$/.test(value);
    // Specifiers and member names built from constants (concatenation, templates,
    // const bindings, type assertions) are evaluated the way the module loader would.
    function constant(node, depth = 0) {
      if (!node || depth > 16) return undefined;
      switch (node.type) {
        case 'Literal': return node.value === null || ['string', 'number', 'boolean', 'bigint'].includes(typeof node.value) ? String(node.value) : undefined;
        case 'TemplateLiteral': {
          let text = '';
          for (const [index, quasi] of node.quasis.entries()) {
            if (typeof quasi.value.cooked !== 'string') return undefined;
            text += quasi.value.cooked;
            if (index < node.expressions.length) {
              const part = constant(node.expressions[index], depth + 1);
              if (part === undefined) return undefined;
              text += part;
            }
          }
          return text;
        }
        case 'BinaryExpression': {
          if (node.operator !== '+') return undefined;
          const left = constant(node.left, depth + 1), right = constant(node.right, depth + 1);
          return left === undefined || right === undefined ? undefined : left + right;
        }
        case 'TSAsExpression': case 'TSSatisfiesExpression': case 'TSNonNullExpression': case 'TSTypeAssertion': case 'ChainExpression':
          return constant(node.expression, depth + 1);
        case 'Identifier': {
          let scope = context.sourceCode.getScope(node);
          while (scope) {
            const variable = scope.set.get(node.name);
            if (variable) {
              const definition = variable.defs.length === 1 ? variable.defs[0] : undefined;
              if (definition?.type !== 'Variable' || definition.parent.kind !== 'const' || definition.node.id.type !== 'Identifier') return undefined;
              return constant(definition.node.init, depth + 1);
            }
            scope = scope.upper;
          }
          return undefined;
        }
        default: return undefined;
      }
    }
    const importedName = specifier => specifier.type === 'ImportSpecifier' ? specifier.imported.name ?? specifier.imported.value : undefined;
    const exportedLocal = specifier => specifier.local.name ?? specifier.local.value;

    if (/^\/src\/(?:node-lnd\/|node-cln\/|approval\/sign\.ts$)/.test(filename)) {
      // Allowed modules may call the capability but never hand it on: not as a value (an
      // export under any name, an object property, an argument, an alias), and not through
      // an exported function that returns the revealed bytes.
      const bound = new Map();
      const exportedNames = new Set();
      const returned = [];
      const literals = [];
      let program;
      const capability = node => (node?.type === 'Identifier' && bound.has(node.name)) ||
        (node?.type === 'MemberExpression' && node.object.type === 'Identifier' && bound.has(node.object.name));
      const reference = node => context.sourceCode.getScope(node).references.some(item => item.identifier === node);
      const called = node => node.parent?.type === 'CallExpression' && node.parent.callee === node;
      const typed = Boolean(context.sourceCode.parserServices?.program);
      // A caller-supplied function or object: rooted in a parameter of an enclosing function.
      function parameter(node) {
        let root = node;
        while (root?.type === 'MemberExpression') root = root.object;
        if (root?.type !== 'Identifier') return false;
        for (let scope = context.sourceCode.getScope(root); scope; scope = scope.upper) {
          const found = scope.set.get(root.name);
          if (found) return found.defs.some(definition => definition.type === 'Parameter');
        }
        return false;
      }
      /**
       * Whether a declaration of this module reaches the capability: it names it, or names a
       * declaration of the module that does (to a fixed point).
       */
      function touchAnalysis() {
        const scopes = context.sourceCode.scopeManager.scopes;
        const moduleScope = scopes.find(scope => scope.type === 'module') ?? scopes[0];
        const references = scopes.flatMap(scope => scope.references);
        const capabilityReference = reference => {
          const name = reference.identifier.name;
          const kind = bound.get(name);
          if (!kind || reference.resolved?.scope !== moduleScope) return false;
          if (kind === 'capability') return true;
          const member = reference.identifier.parent;
          if (member?.type !== 'MemberExpression' || member.object !== reference.identifier) return true;
          const property = member.computed ? constant(member.property) : member.property.name;
          return property === undefined || names.has(property);
        };
        const ranges = new Map();
        for (const variable of moduleScope.variables) {
          const nodes = variable.defs.filter(definition => definition.type !== 'ImportBinding').map(definition => definition.node);
          if (nodes.length > 0) ranges.set(variable, nodes.map(node => node.range));
        }
        const inside = (range, reference) => reference.identifier.range[0] >= range[0] && reference.identifier.range[1] <= range[1];
        const reaches = new Set();
        for (let changed = true; changed;) {
          changed = false;
          for (const [variable, spans] of ranges) {
            if (reaches.has(variable)) continue;
            const hit = references.some(reference => spans.some(span => inside(span, reference)) &&
              (capabilityReference(reference) || (reference.resolved !== null && reaches.has(reference.resolved))));
            if (hit) { reaches.add(variable); changed = true; }
          }
        }
        return node => node?.range !== undefined && references.some(reference => inside(node.range, reference) &&
          (capabilityReference(reference) || (reference.resolved !== null && reaches.has(reference.resolved))));
      }
      // Expressions through which revealed bytes remain the credential.
      const byteMethods = new Set(['toString', 'slice', 'subarray', 'valueOf', 'toJSON', 'toBase64', 'toHex']);
      const byteCopies = /^(?:Buffer|Uint8Array|Array)\.(?:from|of|concat)$|^Promise\.(?:resolve|all|allSettled|any|race)$|^String$|^structuredClone$/;
      function carrier(node) {
        const parent = node.parent;
        switch (parent?.type) {
          case 'TSAsExpression': case 'TSNonNullExpression': case 'TSSatisfiesExpression': case 'TSTypeAssertion':
          case 'AwaitExpression': case 'ChainExpression': case 'LogicalExpression': case 'ArrayExpression':
          case 'SpreadElement': case 'TemplateLiteral': case 'ObjectExpression':
            return parent;
          case 'ConditionalExpression': return parent.test === node ? undefined : parent;
          case 'SequenceExpression': return parent.expressions.at(-1) === node ? parent : undefined;
          case 'Property': return parent.value === node ? parent : undefined;
          case 'MemberExpression': {
            const name = parent.computed ? constant(parent.property) : parent.property.name;
            return parent.object === node && byteMethods.has(name) && called(parent) ? parent.parent : undefined;
          }
          case 'CallExpression': case 'NewExpression': {
            const callee = context.sourceCode.getText(parent.callee);
            const copy = parent.type === 'NewExpression' ? callee === 'Uint8Array' || callee === 'Buffer' : byteCopies.test(callee);
            return copy && parent.arguments.includes(node) ? parent : undefined;
          }
          default: return undefined;
        }
      }
      function exported(fn) {
        for (let node = fn; node?.parent; node = node.parent) {
          if (['FunctionDeclaration', 'ClassDeclaration', 'VariableDeclarator'].includes(node.type) && node.id?.type === 'Identifier' && exportedNames.has(node.id.name)) return true;
          const parent = node.parent;
          if (parent.type === 'ExportNamedDeclaration' || parent.type === 'ExportDefaultDeclaration') return true;
          if (parent.type === 'VariableDeclarator') {
            if (parent.init !== node) return false;
            if (parent.id.type === 'Identifier' && exportedNames.has(parent.id.name)) return true;
            continue;
          }
          if (!['VariableDeclaration', 'MethodDefinition', 'PropertyDefinition', 'Property', 'ClassBody', 'ClassExpression',
            'ClassDeclaration', 'ObjectExpression', 'TSAsExpression', 'TSSatisfiesExpression'].includes(parent.type)) return false;
        }
        return false;
      }
      return {
        Program(node) { program = node; },
        ImportDeclaration(node) {
          if (!secretModule(node.source.value)) return;
          for (const specifier of node.specifiers) {
            const name = importedName(specifier);
            if (name === undefined) bound.set(specifier.local.name, 'namespace');
            else if (names.has(name)) bound.set(specifier.local.name, 'capability');
          }
        },
        Identifier(node) {
          const kind = bound.get(node.name);
          if (!kind || !reference(node)) return;
          if (node.parent.type === 'UnaryExpression' && ['void', 'typeof'].includes(node.parent.operator)) return;
          let use = node;
          if (kind === 'namespace') {
            const member = node.parent;
            if (member.type !== 'MemberExpression' || member.object !== node) { report(node); return; }
            const name = member.computed ? constant(member.property) : member.property.name;
            if (name !== undefined && !names.has(name)) return;
            use = member;
          }
          if (!called(use)) { report(node); return; }
          let value = use.parent;
          for (let next = carrier(value); next; next = carrier(value)) value = next;
          const holder = value.parent;
          if (holder?.type === 'ReturnStatement') {
            const fn = context.sourceCode.getAncestors(holder).findLast(item => /Function/.test(item.type));
            if (fn) returned.push([value, fn]);
          } else if (holder?.type === 'ArrowFunctionExpression' && holder.body === value) returned.push([value, holder]);
          else if (holder?.type === 'VariableDeclarator' && holder.init === value) returned.push([value, holder]);
          else if (holder?.type === 'PropertyDefinition' || holder?.type === 'ExportDefaultDeclaration') report(value);
          // Without type information the exported signatures cannot be judged, so revealed
          // bytes handed to a caller-supplied function or stored on an object are reported.
          else if (!typed && holder?.type === 'CallExpression' && holder.arguments.includes(value) && parameter(holder.callee)) report(value);
          else if (!typed && holder?.type === 'AssignmentExpression' && holder.right === value && holder.left.type === 'MemberExpression') report(value);
        },
        ExportAllDeclaration(node) { if (secretModule(node.source.value)) report(node); },
        ExportNamedDeclaration(node) {
          if (node.source) {
            if (secretModule(node.source.value) && node.specifiers.some(specifier => names.has(exportedLocal(specifier)))) report(node);
            return;
          }
          for (const specifier of node.specifiers) exportedNames.add(exportedLocal(specifier));
          if (node.specifiers.some(specifier => bound.has(exportedLocal(specifier)))) report(node);
          if (node.declaration?.type === 'VariableDeclaration' && node.declaration.declarations.some(item => capability(item.init))) report(node);
        },
        'VariableDeclarator > ObjectExpression.init, VariableDeclarator > ArrayExpression.init, ExportDefaultDeclaration > ObjectExpression, ExportDefaultDeclaration > ArrayExpression'(node) {
          literals.push(node);
        },
        ExportDefaultDeclaration(node) {
          if (node.declaration.type === 'Identifier') exportedNames.add(node.declaration.name);
          if (capability(node.declaration)) report(node);
        },
        'Program:exit'() {
          // A function named in an exported object or array literal is exported too.
          for (let round = 0; round < 3; round++) {
            for (const literal of literals) {
              if (!exported(literal)) continue;
              for (const item of literal.type === 'ObjectExpression' ? literal.properties.map(property => property.value) : literal.elements) {
                if (item?.type === 'Identifier') exportedNames.add(item.name);
              }
            }
          }
          for (const [value, fn] of returned) if (exported(fn)) report(value);
          // A function returning revealed bytes may only be called in this module: any other
          // reference (an alias, an object or array member, a class field, an argument, a
          // default export) would hand it on.
          for (const [, fn] of returned) {
            const declaration = fn.type === 'FunctionDeclaration' ? fn
              : fn.parent?.type === 'VariableDeclarator' && fn.parent.init === fn ? fn.parent : undefined;
            if (!declaration) continue;
            for (const variable of context.sourceCode.getDeclaredVariables(declaration)) {
              for (const { identifier } of variable.references) {
                if (identifier === declaration.id) continue;
                if (!(identifier.parent?.type === 'CallExpression' && identifier.parent.callee === identifier)) report(identifier);
              }
            }
          }
          typedExports(context, filename.slice(1), program, touchAnalysis(), filename === '/src/approval/sign.ts');
        },
      };
    }
    const implementation = /^\/src\/core\/secret\.ts$/.test(filename);
    const computedName = node => { const value = constant(node); return value !== undefined && names.has(value); };
    return {
      Identifier(node) {
        if (!implementation && names.has(node.name)) report(node);
      },
      Literal(node) {
        if (!implementation && typeof node.value === 'string' && names.has(node.value)) report(node);
      },
      'BinaryExpression, TemplateLiteral'(node) {
        if (implementation || (node.parent.type === 'BinaryExpression' && constant(node.parent) !== undefined)) return;
        if (computedName(node)) report(node);
      },
      MemberExpression(node) {
        if (!implementation && node.computed && node.property.type === 'Identifier' && computedName(node.property)) report(node);
      },
      ImportDeclaration(node) {
        if (secretModule(node.source.value) && node.specifiers.some(specifier => importedName(specifier) === undefined || names.has(importedName(specifier)))) report(node);
      },
      ExportNamedDeclaration(node) {
        if (node.source && secretModule(node.source.value) && node.specifiers.some(specifier => names.has(exportedLocal(specifier)))) report(node);
      },
      ExportAllDeclaration(node) { if (secretModule(node.source.value)) report(node); },
      ImportExpression(node) { if (secretModule(constant(node.source))) report(node); },
      CallExpression(node) {
        if (node.callee.type === 'Identifier' && node.callee.name === 'require' && secretModule(constant(node.arguments[0]))) report(node);
      },
    };
  },
};
