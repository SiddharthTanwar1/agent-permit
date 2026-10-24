"""Run from repository root: python -m examples.integration"""
import json
from pathlib import Path

from agent_permit import Context, Denied, Guard, loads

policy = loads((Path(__file__).parent / 'policy.json').read_text())
guard = Guard(policy)
# A real host derives these values from authenticated session claims.
context = Context(principal='support-agent', tenant='acme')


def search_knowledge(collection, query, limit):
    # Replace with a narrow adapter that enforces tenant-level storage permissions.
    # Never interpret query as SQL, shell, a URL, or an instruction to another tool.
    return [{'title': 'Password reset', 'collection': collection}][:limit]


for filename in ['allowed.json', 'denied.json']:
    call = loads((Path(__file__).parent / filename).read_text())
    try:
        result = guard.invoke(call['tool'], call['arguments'], context,
                              {'search_knowledge': search_knowledge},
                              lambda event: print('AUDIT', json.dumps(event)))
        print('RESULT', result)
    except Denied as exc:
        print('DENIED', exc)
