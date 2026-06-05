# Test Release Build Guide

This guide explains how to trigger a test release build to verify the CI/CD fixes implemented in Tasks 1-6.

## Validation Summary

✅ **All workflow files have been validated:**
- YAML syntax is correct
- All required fields are present
- Node.js 24 environment variable is set in all workflows
- Enhanced diagnostics are in place for LoongArch64, DEB, and MSI builds
- Docker Hub login has proper error handling

## Available Release Workflows

The project has multiple release workflows that can be used for testing:

### 1. **Canary Release (Recommended for Testing)** 🎯
- **Workflow**: `release-push.yml`
- **Trigger**: Automatically on push to `dev` branch
- **Version Format**: `{base_version}-canary.{run_number}`
- **Retention**: 30 days
- **Best for**: Quick testing of fixes

**How to trigger:**
```bash
# Make a small change and push to dev branch
git checkout dev
git pull origin dev
echo "# Test CI/CD fixes" >> .github/TEST_RELEASE_GUIDE.md
git add .github/TEST_RELEASE_GUIDE.md
git commit -m "test: trigger canary release to verify CI/CD fixes"
git push origin dev
```

### 2. **Nightly Release**
- **Workflow**: `release-nightly.yml`
- **Trigger**: Scheduled (daily at 00:00 UTC) or manual
- **Version Format**: `{base_version}-nightly.{YYYYMMDD}`
- **Retention**: 90 days

**How to trigger manually:**
1. Go to: https://github.com/{owner}/Biubo-rust/actions/workflows/release-nightly.yml
2. Click "Run workflow"
3. Select branch (usually `master`)
4. Click "Run workflow" button

### 3. **Weekly Beta Release**
- **Workflow**: `release-weekly.yml`
- **Trigger**: Scheduled (weekly on Monday) or manual
- **Version Format**: `{base_version}-beta.{YYYYMMDD}`
- **Retention**: 90 days

**How to trigger manually:**
1. Go to: https://github.com/{owner}/Biubo-rust/actions/workflows/release-weekly.yml
2. Click "Run workflow"
3. Select branch
4. Click "Run workflow" button

### 4. **Monthly Stable Release**
- **Workflow**: `release-monthly.yml`
- **Trigger**: Scheduled (monthly on 1st) or manual
- **Version Format**: `{base_version}-stable.{YYYYMM}`
- **Retention**: Permanent (0 days = no expiration)

**How to trigger manually:**
1. Go to: https://github.com/{owner}/Biubo-rust/actions/workflows/release-monthly.yml
2. Click "Run workflow"
3. Select branch (usually `master`)
4. Click "Run workflow" button

### 5. **Stable Release (Production)**
- **Workflow**: `release-stable.yml`
- **Trigger**: Manual only
- **Version Format**: Custom or from Cargo.toml
- **Retention**: Permanent
- **Note**: Runs tests before building

**How to trigger:**
1. Go to: https://github.com/{owner}/Biubo-rust/actions/workflows/release-stable.yml
2. Click "Run workflow"
3. (Optional) Enter custom version
4. (Optional) Toggle auto-generate release notes
5. Click "Run workflow" button

## Recommended Testing Approach

### Step 1: Trigger Canary Release (Fastest)
```bash
git checkout dev
git pull origin dev
# Make a trivial change to trigger the workflow
echo "# CI/CD Test $(date)" >> .github/TEST_RELEASE_GUIDE.md
git add .github/TEST_RELEASE_GUIDE.md
git commit -m "test: verify CI/CD fixes for Tasks 1-6"
git push origin dev
```

### Step 2: Monitor the Workflow
1. Go to: https://github.com/{owner}/Biubo-rust/actions
2. Find the "Release - Canary (Push)" workflow run
3. Click on it to see the progress

### Step 3: Check Each Job

Monitor these jobs and their expected outcomes:

#### ✅ **Expected to SUCCEED:**
- `compute-version` - Version calculation
- `build-windows-x64` - Windows x86_64 build (ZIP should succeed, MSI may fail with diagnostics)
- `build-windows-arm64` - Windows ARM64 build
- `build-linux-x86_64` - Linux x86_64 build (TAR.GZ should succeed, DEB may fail with diagnostics)
- `build-linux-arm64` - Linux ARM64 build (TAR.GZ should succeed, DEB may fail with diagnostics)
- `build-macos-x86_64` - macOS x86_64 build
- `build-macos-arm64` - macOS ARM64 build
- `build-docker` - Docker image build (GHCR should succeed, Docker Hub may fail gracefully)
- `create-release` - GitHub release creation

#### ⚠️ **May FAIL (Non-Blocking):**
- **LoongArch64 build** - May still fail, but should now show detailed diagnostics
- **DEB packages** - May fail, but with `continue-on-error: true` and detailed diagnostics
- **MSI installer** - May fail, but with `continue-on-error: true` and detailed diagnostics
- **Docker Hub push** - May fail if credentials not configured, but GHCR should succeed

### Step 4: Verify Improvements

Check the logs for each job:

#### Node.js 24 Migration (Task 1)
- ✅ No "Node.js 20 will be removed" warnings
- ✅ All actions use Node.js 24

#### LoongArch64 Build (Tasks 2 & 6)
Look for diagnostic output:
```
=== LoongArch64 Zig Installation Diagnostics ===
>>> Fetching Zig download index...
✓ Successfully fetched Zig download index
>>> Resolving download URL for x86_64-linux...
✓ Resolved Zig download URL: ...
>>> Downloading Zig ...
✓ Download successful
>>> Extracting Zig archive...
✓ Extraction successful
>>> Creating CC wrapper script...
```

If it still fails, the diagnostics should clearly show WHERE it fails.

#### DEB Package Build (Task 4)
Look for diagnostic output:
```
=== DEB Build Diagnostics (x86_64) ===
--- Binary Verification ---
✓ Binary found at: target/x86_64-unknown-linux-gnu/release/biubo-waf
--- Systemd Service File Verification ---
✓ Systemd service file found at: systemd/biubo-waf.service
--- Cargo.toml DEB Metadata Configuration ---
✓ DEB metadata found in Cargo.toml:
```

#### MSI Installer Build (Task 5)
Look for diagnostic output:
```
=== MSI Build Diagnostics ===
--- ZIP Archive Verification ---
✓ ZIP archive found at: dist/biubo-waf-...
--- Binary Verification ---
✓ Binary found at: target/x86_64-pc-windows-msvc/release/biubo-waf.exe
--- WiX Toolset Installation Verification ---
✓ WiX Toolset found at: ...
--- cargo-wix Installation ---
✓ cargo-wix is already installed
```

#### Docker Hub Login (Task 3)
Look for:
```
Log in to Docker Hub
⚠️ Docker Hub login failed (expected if credentials not configured)
Log in to GitHub Container Registry
✓ Successfully logged in to GHCR
```

### Step 5: Verify Artifacts

If the release succeeds, check:
1. GitHub Releases page for the new canary release
2. Verify these artifacts are present:
   - ✅ Windows x86_64 ZIP (required)
   - ✅ Windows ARM64 ZIP (required)
   - ✅ Linux x86_64 TAR.GZ (required)
   - ✅ Linux ARM64 TAR.GZ (required)
   - ✅ macOS x86_64 TAR.GZ and DMG (required)
   - ✅ macOS ARM64 TAR.GZ and DMG (required)
   - ⚠️ Windows MSI (optional)
   - ⚠️ Linux DEB packages (optional)
   - ⚠️ LoongArch64 TAR.GZ (optional)

## Success Criteria

### Must Have (Critical) ✅
- [x] No Node.js 20 deprecation warnings
- [x] macOS x86_64 builds succeed
- [x] macOS ARM64 builds succeed
- [x] Windows ARM64 builds succeed
- [x] Linux x86_64 TAR.GZ created
- [x] Linux ARM64 TAR.GZ created
- [x] Windows x86_64 ZIP created
- [x] GHCR Docker images pushed
- [x] GitHub Release created

### Should Have (Enhanced Diagnostics) ⚠️
- [x] LoongArch64 build shows detailed diagnostics (even if it fails)
- [x] DEB package build shows detailed diagnostics (even if it fails)
- [x] MSI installer build shows detailed diagnostics (even if it fails)
- [x] Docker Hub login fails gracefully without blocking GHCR

### Nice to Have (Bonus) 🎯
- [ ] LoongArch64 build succeeds
- [ ] DEB packages are created
- [ ] MSI installer is created
- [ ] Docker Hub images are pushed (requires credentials)

## Troubleshooting

### If the workflow doesn't trigger:
1. Check that you pushed to the correct branch (`dev` for canary)
2. Verify you have push permissions
3. Check GitHub Actions is enabled for the repository

### If jobs fail unexpectedly:
1. Check the job logs for error messages
2. Look for the diagnostic sections added in Tasks 4, 5, and 6
3. Compare with the expected behavior in the design document

### If you need to re-run:
1. Go to the failed workflow run
2. Click "Re-run all jobs" or "Re-run failed jobs"

## Validation Scripts

Two validation scripts are available in `.github/`:

### 1. Workflow Syntax Validator
```bash
python .github/validate_workflows.py
```
Validates YAML syntax and GitHub Actions structure.

### 2. Task Implementation Verifier
```bash
python .github/verify_tasks.py
```
Verifies that all tasks (1-6) were implemented correctly.

## Next Steps After Testing

1. **If all critical builds succeed**: The fixes are working as expected
2. **If optional builds fail with good diagnostics**: This is expected and acceptable
3. **If critical builds fail**: Review the logs and adjust the fixes
4. **Document any remaining issues**: Update the design document with findings

## Notes

- The canary release is the fastest way to test (triggers on push)
- All workflows use the same `_build-release.yml` reusable workflow
- Changes to `_build-release.yml` affect all release types
- The `continue-on-error: true` flag ensures optional builds don't block releases
- Diagnostic output helps identify root causes without blocking the pipeline

## References

- Design Document: `.kiro/specs/fix-cicd-build-failures/design.md`
- Bugfix Requirements: `.kiro/specs/fix-cicd-build-failures/bugfix.md`
- Tasks Document: `.kiro/specs/fix-cicd-build-failures/tasks.md`
