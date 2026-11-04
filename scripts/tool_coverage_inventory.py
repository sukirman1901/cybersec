"""Offline static inventory. Test references are not execution/accuracy evidence."""
import ast
import json
from pathlib import Path


def build_inventory(root):
    root = Path(root)
    server = ast.parse((root / 'mcp/server.py').read_text())
    imports = {}
    for node in ast.walk(server):
        if isinstance(node, ast.ImportFrom) and (node.module or '').startswith('cyber_tools.'):
            for alias in node.names:
                imports[alias.asname or alias.name] = ('mcp/' + node.module.replace('.', '/') + '.py', alias.name)
    tests = {str(p.relative_to(root)): p.read_text() for p in sorted((root / 'mcp/tests').glob('test_*.py'))}
    tools = []
    for node in server.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not any(isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
                   and isinstance(d.func.value, ast.Name) and d.func.value.id == 'mcp'
                   and d.func.attr == 'tool' for d in node.decorator_list):
            continue
        called = {n.func.id for n in ast.walk(node) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        implementations = sorted({imports[name][0] for name in called if name in imports})
        if not implementations:
            implementations = ['mcp/server.py']
        symbols = {node.name} | {imports[name][1] for name in called if name in imports}
        # Token boundaries avoid counting substring collisions; this is still a
        # static candidate list, not a trace of which function ran in a test.
        import re
        pattern = re.compile(r'\b(?:' + '|'.join(re.escape(s) for s in sorted(symbols)) + r')\b')
        references = [path for path, text in tests.items() if pattern.search(text)]
        dependencies = set()
        for path in implementations:
            for item in ast.walk(ast.parse((root / path).read_text())):
                if isinstance(item, ast.Import):
                    dependencies.update(a.name.split('.')[0] for a in item.names)
                elif isinstance(item, ast.ImportFrom) and item.level == 0 and item.module:
                    dependencies.add(item.module.split('.')[0])
        tools.append({'name': node.name, 'description': ast.get_docstring(node) or '',
                      'implementation_files': implementations,
                      'import_roots': sorted(dependencies),
                      'static_test_references': references,
                      'accuracy': 'not_measured_by_inventory',
                      'latency_p95_ms': None, 'requests_per_run': None})
    tools.sort(key=lambda t: t['name'])
    return {'schema_version': 1, 'tool_count': len(tools),
            'with_static_test_references': sum(bool(t['static_test_references']) for t in tools),
            'limitations': ['Static references can include generic contract tests, strings and mocks.',
                            'No scanner executed. No accuracy or runtime coverage inferred.',
                            'Import roots include stdlib; CLI/API/browser prerequisites need per-tool review.'],
            'tools': tools}


if __name__ == '__main__':
    print(json.dumps(build_inventory(Path(__file__).resolve().parents[1]), indent=2))
