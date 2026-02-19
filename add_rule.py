#!/usr/bin/env python3
"""
Add custom monitoring rules with risk scores
Usage: python add_rule.py --path C:\Users\something\secret.txt --score 0.9
       python add_rule.py --path C:\Users\something\ --score 0.8 --recursive
"""

import os
import json
import argparse
import sys
from pathlib import Path

CONFIG_FILE = 'user_rules.json'

def load_rules():
    """Load existing rules"""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except:
            return {'monitor_paths': [], 'risk_scores': {}}
    return {'monitor_paths': [], 'risk_scores': {}}

def save_rules(rules):
    """Save rules to file"""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(rules, f, indent=4)
    print(f"✅ Rules saved to {CONFIG_FILE}")

def main():
    parser = argparse.ArgumentParser(description='Add custom monitoring paths with risk scores')
    parser.add_argument('--path', required=True, help='File or folder path to monitor')
    parser.add_argument('--score', type=float, default=0.5, help='Risk score (0.0 to 1.0, default: 0.5)')
    parser.add_argument('--recursive', action='store_true', help='Monitor folder recursively')
    parser.add_argument('--list', action='store_true', help='List all current rules')
    parser.add_argument('--remove', metavar='PATH', help='Remove a rule')
    
    args = parser.parse_args()
    
    rules = load_rules()
    
    if args.list:
        print("\n📋 Current Monitoring Rules:")
        print("="*50)
        if rules['monitor_paths']:
            for item in rules['monitor_paths']:
                path = item['path']
                score = item.get('score', 0.5)
                recursive = item.get('recursive', False)
                print(f"  • {path} (score: {score}, recursive: {recursive})")
        else:
            print("  No custom rules defined")
        return
    
    if args.remove:
        path_to_remove = os.path.abspath(args.remove)
        rules['monitor_paths'] = [p for p in rules['monitor_paths'] 
                                   if p['path'] != path_to_remove]
        if path_to_remove in rules['risk_scores']:
            del rules['risk_scores'][path_to_remove]
        save_rules(rules)
        print(f"✅ Removed rule for: {path_to_remove}")
        return
    
    # Add new rule
    abs_path = os.path.abspath(args.path)
    
    if not os.path.exists(abs_path):
        print(f"❌ Path does not exist: {abs_path}")
        return
    
    # Validate score
    if args.score < 0 or args.score > 1:
        print("❌ Score must be between 0.0 and 1.0")
        return
    
    # Add to monitor_paths
    new_rule = {
        'path': abs_path,
        'score': args.score,
        'recursive': args.recursive,
        'type': 'folder' if os.path.isdir(abs_path) else 'file'
    }
    
    # Remove if already exists
    rules['monitor_paths'] = [p for p in rules['monitor_paths'] 
                               if p['path'] != abs_path]
    
    rules['monitor_paths'].append(new_rule)
    
    # Also store in risk_scores for quick lookup
    if os.path.isfile(abs_path):
        rules['risk_scores'][abs_path] = args.score
    
    save_rules(rules)
    
    path_type = "Folder" if os.path.isdir(abs_path) else "File"
    recursive_str = " (recursive)" if args.recursive else ""
    print(f"✅ Added {path_type}: {abs_path}")
    print(f"   Risk score: {args.score}{recursive_str}")

if __name__ == "__main__":
    main()