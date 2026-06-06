#!/usr/bin/env python3
"""
GitHub Actions Workflow Validation Script
Validates workflow files for syntax and common issues
"""

import yaml
import sys
import glob
from pathlib import Path

def validate_workflow(filepath):
    """Validate a single workflow file"""
    errors = []
    warnings = []
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            workflow = yaml.safe_load(content)
        
        # Check for required top-level keys
        if 'name' not in workflow:
            warnings.append(f"Missing 'name' field")
        
        # Check for 'on' field (can be True/False boolean or dict)
        # YAML treats 'on' as a boolean keyword, so check for both 'on' and True
        if 'on' not in workflow and True not in workflow:
            errors.append(f"Missing 'on' trigger field (required)")
        
        if 'jobs' not in workflow:
            errors.append(f"Missing 'jobs' field (required)")
        
        # Check for Node.js 24 environment variable
        has_node24_env = False
        if 'env' in workflow:
            if 'FORCE_JAVASCRIPT_ACTIONS_TO_NODE24' in workflow['env']:
                has_node24_env = True
        
        if not has_node24_env:
            warnings.append(f"Missing FORCE_JAVASCRIPT_ACTIONS_TO_NODE24 environment variable")
        
        # Check jobs structure
        if 'jobs' in workflow:
            for job_name, job_config in workflow['jobs'].items():
                if not isinstance(job_config, dict):
                    errors.append(f"Job '{job_name}' is not a dictionary")
                    continue
                
                # Check for runs-on or uses (one is required)
                if 'runs-on' not in job_config and 'uses' not in job_config:
                    errors.append(f"Job '{job_name}' missing 'runs-on' or 'uses' field")
                
                # Check steps structure if present
                if 'steps' in job_config:
                    if not isinstance(job_config['steps'], list):
                        errors.append(f"Job '{job_name}' steps is not a list")
                    else:
                        for idx, step in enumerate(job_config['steps']):
                            if not isinstance(step, dict):
                                errors.append(f"Job '{job_name}' step {idx} is not a dictionary")
                            elif 'uses' not in step and 'run' not in step:
                                errors.append(f"Job '{job_name}' step {idx} missing 'uses' or 'run' field")
        
        return errors, warnings
        
    except yaml.YAMLError as e:
        return [f"YAML parsing error: {e}"], []
    except Exception as e:
        return [f"Unexpected error: {e}"], []

def main():
    """Main validation function"""
    workflow_dir = Path('.github/workflows')
    
    if not workflow_dir.exists():
        print(f"Error: Workflow directory '{workflow_dir}' not found")
        sys.exit(1)
    
    workflow_files = list(workflow_dir.glob('*.yml')) + list(workflow_dir.glob('*.yaml'))
    
    if not workflow_files:
        print(f"Warning: No workflow files found in '{workflow_dir}'")
        sys.exit(0)
    
    print(f"Validating {len(workflow_files)} workflow files...\n")
    
    total_errors = 0
    total_warnings = 0
    
    for filepath in sorted(workflow_files):
        print(f"📄 {filepath.name}")
        errors, warnings = validate_workflow(filepath)
        
        if errors:
            print(f"  ❌ {len(errors)} error(s):")
            for error in errors:
                print(f"     - {error}")
            total_errors += len(errors)
        
        if warnings:
            print(f"  ⚠️  {len(warnings)} warning(s):")
            for warning in warnings:
                print(f"     - {warning}")
            total_warnings += len(warnings)
        
        if not errors and not warnings:
            print(f"  ✅ Valid")
        
        print()
    
    print("=" * 60)
    print(f"Summary: {len(workflow_files)} files validated")
    print(f"  Errors: {total_errors}")
    print(f"  Warnings: {total_warnings}")
    print("=" * 60)
    
    if total_errors > 0:
        print("\n❌ Validation FAILED - please fix errors before proceeding")
        sys.exit(1)
    elif total_warnings > 0:
        print("\n⚠️  Validation passed with warnings")
        sys.exit(0)
    else:
        print("\n✅ All workflow files are valid!")
        sys.exit(0)

if __name__ == '__main__':
    main()
