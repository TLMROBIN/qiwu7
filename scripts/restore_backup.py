#!/usr/bin/env python3
"""Build a recovery candidate using reverse deltas; never overwrite live state."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from qiwu7_security import restore_delta


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('state', type=Path)
    parser.add_argument('backups', type=Path)
    parser.add_argument('target_rev', type=int)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    state = json.loads(args.state.read_text())
    if args.target_rev > state['rev']: parser.error('目标版本大于当前版本')
    while state['rev'] > args.target_rev:
        files = list(args.backups.glob('delta-%s-*.json' % (state['rev']-1)))
        if len(files) != 1: parser.error('缺失或重复的增量备份：%s' % (state['rev']-1))
        state = restore_delta(state, json.loads(files[0].read_text()))
    # Exclusive creation prevents overwriting state.json or an existing recovery candidate.
    with args.output.open('x', encoding='utf-8') as f:
        args.output.chmod(0o600)
        json.dump(state, f, ensure_ascii=False)
    print('Recovery candidate created at revision', state['rev'])


if __name__ == '__main__':
    main()
