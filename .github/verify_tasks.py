#!/usr/bin/env python3
"""
Verification script for CI/CD fix tasks
"""

import yaml
import os
from pathlib import Path

def check_task1_node24_env():
    """Task 1: Verify Node.js 24 environment variable in all workflows"""
    print('Task 1: Node.js 24 Environment Variable')
    print('-' * 60)
    
    workflow_dir = Path('.github/workflows')
    all_pass = True
    
    for wf_file in sorted(workflow_dir.glob('*.yml')):
        with open(wf_file, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
            has_env = 'env' in data and 'FORCE_JAVASCRIPT_ACTIONS_TO_NODE24' in data.get('env', {})
            status = '✅' if has_env else '❌'
            print(f'{status} {wf_file.name}: {"Present" if has_env else "MISSING"}')
            if not has_env:
                all_pass = False
    
    print()
    return all_pass

def check_task2_zig_wrapper():
    """Task 2: Verify enhanced Zig wrapper script"""
    print('Task 2: Enhanced LoongArch64 Zig Wrapper Script')
    print('-' * 60)
    
    wf_file = Path('.github/workflows/_build-release.yml')
    with open(wf_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check for additional flag filtering
    flags_to_check = ['-fPIC', '-fPIE', '-fno-pic', '-fno-pie', '-fno-plt']
    found_flags = []
    missing_flags = []
    
    for flag in flags_to_check:
        if flag in content:
            found_flags.append(flag)
        else:
            missing_flags.append(flag)
    
    if not missing_flags:
        print(f'✅ All required flags are filtered: {", ".join(flags_to_check)}')
        print()
        return True
    else:
        print(f'❌ Missing flag filtering for: {", ".join(missing_flags)}')
        print(f'✅ Found filtering for: {", ".join(found_flags)}')
        print()
        return False

def check_task3_docker_hub():
    """Task 3: Verify Docker Hub login error handling"""
    print('Task 3: Docker Hub Login Error Handling')
    print('-' * 60)
    
    wf_file = Path('.github/workflows/_build-release.yml')
    with open(wf_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check for continue-on-error in Docker Hub login
    has_continue_on_error = 'continue-on-error: true' in content and 'Log in to Docker Hub' in content
    
    if has_continue_on_error:
        print('✅ Docker Hub login has continue-on-error: true')
        print()
        return True
    else:
        print('❌ Docker Hub login missing continue-on-error: true')
        print()
        return False

def check_task4_deb_diagnostics():
    """Task 4: Verify DEB package build diagnostics"""
    print('Task 4: DEB Package Build Diagnostics')
    print('-' * 60)
    
    wf_file = Path('.github/workflows/_build-release.yml')
    with open(wf_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check for diagnostic sections
    diagnostics = [
        'DEB Build Diagnostics',
        'Binary Verification',
        'Systemd Service File Verification',
        'Cargo.toml DEB Metadata Configuration'
    ]
    
    found = []
    missing = []
    
    for diag in diagnostics:
        if diag in content:
            found.append(diag)
        else:
            missing.append(diag)
    
    if not missing:
        print(f'✅ All diagnostic sections present:')
        for d in found:
            print(f'   - {d}')
        print()
        return True
    else:
        print(f'❌ Missing diagnostic sections:')
        for d in missing:
            print(f'   - {d}')
        print()
        return False

def check_task5_msi_diagnostics():
    """Task 5: Verify Windows MSI build diagnostics"""
    print('Task 5: Windows MSI Build Diagnostics')
    print('-' * 60)
    
    wf_file = Path('.github/workflows/_build-release.yml')
    with open(wf_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check for diagnostic sections
    diagnostics = [
        'MSI Build Diagnostics',
        'WiX Toolset Installation Verification',
        'cargo-wix Installation',
        'WiX Configuration Files'
    ]
    
    found = []
    missing = []
    
    for diag in diagnostics:
        if diag in content:
            found.append(diag)
        else:
            missing.append(diag)
    
    if not missing:
        print(f'✅ All diagnostic sections present:')
        for d in found:
            print(f'   - {d}')
        print()
        return True
    else:
        print(f'❌ Missing diagnostic sections:')
        for d in missing:
            print(f'   - {d}')
        print()
        return False

def check_task6_zig_diagnostics():
    """Task 6: Verify LoongArch64 Zig installation diagnostics"""
    print('Task 6: LoongArch64 Zig Installation Diagnostics')
    print('-' * 60)
    
    wf_file = Path('.github/workflows/_build-release.yml')
    with open(wf_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check for diagnostic sections
    diagnostics = [
        'LoongArch64 Zig Installation Diagnostics',
        'set -x',  # Verbose shell output
        'Fetching Zig download index',
        'Resolving download URL',
        'Downloading Zig',
        'Extracting Zig archive'
    ]
    
    found = []
    missing = []
    
    for diag in diagnostics:
        if diag in content:
            found.append(diag)
        else:
            missing.append(diag)
    
    if not missing:
        print(f'✅ All diagnostic sections present:')
        for d in found:
            print(f'   - {d}')
        print()
        return True
    else:
        print(f'❌ Missing diagnostic sections:')
        for d in missing:
            print(f'   - {d}')
        if found:
            print(f'✅ Found:')
            for d in found:
                print(f'   - {d}')
        print()
        return False

def main():
    print('=' * 60)
    print('CI/CD Build Fixes - Task Verification')
    print('=' * 60)
    print()
    
    results = {
        'Task 1': check_task1_node24_env(),
        'Task 2': check_task2_zig_wrapper(),
        'Task 3': check_task3_docker_hub(),
        'Task 4': check_task4_deb_diagnostics(),
        'Task 5': check_task5_msi_diagnostics(),
        'Task 6': check_task6_zig_diagnostics(),
    }
    
    print('=' * 60)
    print('Summary')
    print('=' * 60)
    
    for task, passed in results.items():
        status = '✅ PASS' if passed else '❌ FAIL'
        print(f'{status} - {task}')
    
    print()
    
    all_passed = all(results.values())
    if all_passed:
        print('✅ All tasks verified successfully!')
        return 0
    else:
        failed_count = sum(1 for v in results.values() if not v)
        print(f'❌ {failed_count} task(s) failed verification')
        return 1

if __name__ == '__main__':
    import sys
    sys.exit(main())
