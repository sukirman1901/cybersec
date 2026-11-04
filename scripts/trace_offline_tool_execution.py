"""Trace real Python tool-entry calls during network-disabled unittest cases.

No arguments, locals, return values or token values are captured. A call trace is
execution evidence for that fixture, not operational accuracy or branch coverage.
"""
import ast
import json
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch

import run_offline_tests as offline

ROOT = Path(__file__).resolve().parents[1]


def mappings():
    tree = ast.parse((ROOT/'mcp/server.py').read_text())
    imports = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or '').startswith('cyber_tools.'):
            for alias in node.names:
                imports[alias.asname or alias.name] = ('mcp/'+node.module.replace('.', '/')+'.py', alias.name)
    tools = {}
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not any(isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
                   and isinstance(d.func.value, ast.Name) and d.func.value.id == 'mcp'
                   and d.func.attr == 'tool' for d in node.decorator_list):
            continue
        names = {n.func.id for n in ast.walk(node) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        tools[node.name] = sorted({imports[name] for name in names if name in imports}) or [('mcp/server.py', node.name)]
    return tools


def main():
    tools = mappings()
    expected = {}
    for entries in tools.values():
        for path, symbol in entries:
            # Public imports can alias a function whose code retains its original
            # qualname (e.g. scan_vulnerabilities = vuln_scanner).
            tree = ast.parse((ROOT/path).read_text())
            aliases = {target.id: node.value.id for node in tree.body
                       if isinstance(node, ast.Assign) and isinstance(node.value, ast.Name)
                       for target in node.targets if isinstance(target, ast.Name)}
            actual, seen = symbol, set()
            while actual in aliases and actual not in seen:
                seen.add(actual)
                actual = aliases[actual]
            expected.setdefault((str(ROOT/path), actual), set()).add((path, symbol))
    calls = {entry:set() for entries in tools.values() for entry in entries}
    current = [None]

    class Result(unittest.TextTestResult):
        def startTest(self, test):
            current[0] = test.id()
            super().startTest(test)

        def stopTest(self, test):
            super().stopTest(test)
            current[0] = None

    def observe(frame, event, arg):
        if event == 'call' and current[0] is not None:
            key = (frame.f_code.co_filename, frame.f_code.co_qualname)
            if key in expected:
                for entry in expected[key]:
                    calls[entry].add(current[0])

    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(name) for name in offline.MODULES)
    with patch.object(socket.socket, 'connect', offline.deny_network), patch.object(socket.socket, 'connect_ex', offline.deny_network):
        sys.setprofile(observe)
        try:
            result = unittest.TextTestRunner(verbosity=1, resultclass=Result).run(suite)
        finally:
            sys.setprofile(None)
    rows = []
    for name, entries in sorted(tools.items()):
        observed = sorted({test for entry in entries for test in calls[entry]})
        rows.append({'tool':name, 'mapped_entries':[{'path':path,'symbol':symbol} for path,symbol in entries],
                     'entry_execution_observed':bool(observed), 'test_ids':observed,
                     'verdict':'fixture_execution_observed' if observed else 'not_observed_in_this_run'})
    report = {'catalog_count':len(rows), 'entry_execution_observed':sum(row['entry_execution_observed'] for row in rows),
              'tests_run':result.testsRun, 'tests_successful':result.wasSuccessful(),
              'failures':len(result.failures), 'errors':len(result.errors), 'tools':rows,
              'limitations':['Main-thread Python calls only; subprocess/CLI/browser execution is not traced.',
                             'Test IDs identify cases that called mapped implementation entries, not every action or branch.',
                             'Mocks may satisfy dependencies; an entry call is not an operational pass or proof of accuracy.',
                             'No live target tested; no sensitive argument/return values recorded.']}
    print(json.dumps(report, indent=2))
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(main())
