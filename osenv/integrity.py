"""Bounded source-policy checks; semantic completeness still requires review."""
import ast
from pathlib import Path
import re
import subprocess
import sys


def inspect_source(path, local_modules):
    errors = []
    source = path.read_text()
    if re.search(r'(?m)^\s*(?:#|;|//|/\*)\s*(?:TODO|FIXME|STUB|PLACEHOLDER)\b', source):
        errors.append('unresolved implementation marker')
    if path.suffix != '.py':
        return errors
    tree = ast.parse(source, filename=str(path))
    for node in ast.walk(tree):
        names = []
        if isinstance(node, ast.Import):
            names = [x.name.split('.')[0] for x in node.names]
        elif isinstance(node, ast.ImportFrom) and not node.level:
            names = [(node.module or '').split('.')[0]]
        for name in names:
            if name not in sys.stdlib_module_names and name not in local_modules:
                errors.append(f'line {node.lineno}: external import {name}')
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            body = list(node.body)
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
                body = body[1:]
            if not body or all(isinstance(x, ast.Pass) or isinstance(x, ast.Expr) and isinstance(x.value, ast.Constant) and x.value.value is Ellipsis for x in body):
                errors.append(f'line {node.lineno}: empty implementation {node.name}')
        if isinstance(node, ast.Name) and node.id in {'NotImplemented', 'NotImplementedError'}:
            errors.append(f'line {node.lineno}: placeholder implementation')
    return errors


def audit(root, os_only=False):
    root = Path(root).resolve()
    files = subprocess.run(['git', '-C', str(root), 'ls-files', '-z', '--cached', '--others', '--exclude-standard'],
                           capture_output=True, check=True, timeout=10).stdout.split(b'\0')
    paths = sorted({Path(x.decode()) for x in files if x})
    modules = {p.parts[0] for p in paths if len(p.parts) > 1 and p.name == '__init__.py'}
    modules |= {p.stem for p in paths if len(p.parts) == 1 and p.suffix == '.py'}
    findings = []
    checked = 0
    for relative in paths:
        path = root / relative
        if not path.exists():
            continue  # staged deletion, not shipped source
        errors = []
        if os_only and (relative.parts[0] in {'fixture', 'osenv'} or str(relative) in {'dev', '.gitmodules'} or str(relative).startswith('tools/osenv')):
            errors.append('harness content is forbidden in the OS repository')
        if path.is_symlink():
            errors.append('source symlink requires removal; audit cannot follow external source')
        elif path.is_dir():
            errors.append('vendored Git submodule is forbidden')
        elif path.name in {'pyproject.toml', 'requirements.txt', 'requirements-dev.txt', 'package.json', 'Cargo.toml', 'Pipfile', 'poetry.lock', 'uv.lock'} or path.suffix in {'.so', '.dylib', '.a', '.dll', '.o', '.img', '.qcow2', '.dump', '.core'}:
            errors.append('dependency/package manifest or generated binary is forbidden')
        elif path.suffix in {'.py', '.c', '.h', '.asm', '.S', '.s'}:
            checked += 1
            try:
                errors.extend(inspect_source(path, modules))
            except (SyntaxError, UnicodeError) as error:
                errors.append(str(error))
        if errors:
            findings.append({'path': str(relative), 'errors': errors})
    return {'ok': not findings, 'repository': str(root), 'source_files_checked': checked,
            'findings': findings, 'scope': 'source policy only; not proof of originality, completeness or boot'}
