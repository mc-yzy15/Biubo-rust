# CI/CD Configuration Guide

This document provides configuration instructions for repository maintainers to set up optional CI/CD features for the Biubo WAF project.

## Table of Contents

- [Docker Hub Image Publishing](#docker-hub-image-publishing)
  - [Overview](#overview)
  - [Prerequisites](#prerequisites)
  - [Configuration Steps](#configuration-steps)
  - [Verification](#verification)
  - [Troubleshooting](#troubleshooting)
- [Release Workflow Overview](#release-workflow-overview)

---

## Docker Hub Image Publishing

### Overview

The Biubo WAF CI/CD pipeline supports publishing Docker images to two container registries:

1. **GitHub Container Registry (GHCR)** - *Always enabled* (uses `GITHUB_TOKEN` automatically)
2. **Docker Hub** - *Optional* (requires manual secret configuration)

By default, Docker images are published to GHCR at `ghcr.io/<owner>/biubo-rust`. If you want to also publish images to Docker Hub (e.g., `yourusername/biubo-waf`), you need to configure Docker Hub credentials as repository secrets.

**Note**: Docker Hub publishing is completely optional. The CI/CD pipeline is designed to gracefully handle missing Docker Hub credentials and will continue to publish to GHCR successfully.

### Prerequisites

Before configuring Docker Hub secrets, you need:

1. **A Docker Hub account** - Sign up at [hub.docker.com](https://hub.docker.com) if you don't have one
2. **A Docker Hub access token** - For security, use an access token instead of your password
3. **Repository admin access** - You need admin permissions on the GitHub repository to add secrets

### Configuration Steps

#### Step 1: Create a Docker Hub Access Token

1. Log in to [Docker Hub](https://hub.docker.com)
2. Click on your username in the top-right corner and select **Account Settings**
3. Navigate to **Security** → **Access Tokens**
4. Click **New Access Token**
5. Configure the token:
   - **Description**: `GitHub Actions - Biubo WAF` (or any descriptive name)
   - **Access permissions**: Select **Read, Write, Delete** (required for pushing images)
6. Click **Generate**
7. **Important**: Copy the token immediately - you won't be able to see it again!

#### Step 2: Add Secrets to GitHub Repository

1. Navigate to your GitHub repository
2. Go to **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret**
4. Add the first secret:
   - **Name**: `DOCKERHUB_USERNAME`
   - **Secret**: Your Docker Hub username (e.g., `johndoe`)
   - Click **Add secret**
5. Click **New repository secret** again
6. Add the second secret:
   - **Name**: `DOCKERHUB_TOKEN`
   - **Secret**: Paste the access token you generated in Step 1
   - Click **Add secret**

#### Step 3: Verify Secret Configuration

After adding both secrets, you should see them listed in the repository secrets page:

```
DOCKERHUB_USERNAME
DOCKERHUB_TOKEN
GITHUB_TOKEN (automatically provided by GitHub)
```

**Security Note**: The secret values are encrypted and cannot be viewed after creation. Only the secret names are visible.

### Verification

To verify that Docker Hub publishing is working correctly:

1. **Trigger a release workflow** (or wait for the next scheduled release)
2. **Monitor the workflow run**:
   - Go to **Actions** tab in your GitHub repository
   - Click on the running workflow
   - Navigate to the **build-docker** job
3. **Check the logs**:
   - The "Log in to Docker Hub" step should show: ✅ **Success**
   - The "Build and push Docker image" step should show images being pushed to both registries:
     ```
     Pushing to docker.io/yourusername/biubo-waf:latest
     Pushing to ghcr.io/yourorg/biubo-rust:latest
     ```

4. **Verify on Docker Hub**:
   - Visit `https://hub.docker.com/r/yourusername/biubo-waf`
   - You should see the newly pushed image with appropriate tags

### Troubleshooting

#### Docker Hub Login Fails

**Symptom**: The "Log in to Docker Hub" step shows an error like "Username and password required"

**Solutions**:
- Verify both `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` secrets are configured
- Check that the username matches your Docker Hub account exactly (case-sensitive)
- Ensure the access token has not expired or been revoked
- Regenerate the access token if necessary and update the `DOCKERHUB_TOKEN` secret

#### Images Not Appearing on Docker Hub

**Symptom**: Workflow succeeds but images don't appear on Docker Hub

**Solutions**:
- Verify the access token has **Read, Write, Delete** permissions
- Check that the Docker Hub repository exists (it should be auto-created on first push)
- Review the "Build and push Docker image" step logs for push errors
- Ensure your Docker Hub account has not reached storage limits

#### "Repository does not exist" Error

**Symptom**: Push fails with "repository does not exist or may require 'docker login'"

**Solutions**:
- Docker Hub should auto-create repositories on first push
- If using an organization account, ensure the token has permissions for that organization
- Manually create the repository on Docker Hub: `yourusername/biubo-waf`

#### Workflow Continues Despite Docker Hub Failure

**This is expected behavior!** The CI/CD pipeline is designed with graceful degradation:

- If Docker Hub login fails, the workflow continues and publishes to GHCR only
- The "Log in to Docker Hub" step has `continue-on-error: true`
- This ensures releases are not blocked by optional Docker Hub publishing

If you see Docker Hub failures but GHCR succeeds, the release is still valid. You can fix the Docker Hub configuration and the next release will publish to both registries.

---

## Release Workflow Overview

The Biubo WAF project uses multiple release workflows:

- **`release-stable.yml`** - Stable releases (manual trigger)
- **`release-weekly.yml`** - Weekly releases (scheduled)
- **`release-nightly.yml`** - Nightly builds (scheduled)
- **`release-monthly.yml`** - Monthly releases (scheduled)
- **`release-push.yml`** - Release on push to main branch

All workflows use the shared `_build-release.yml` workflow, which handles:
- Building binaries for multiple platforms (Linux, macOS, Windows, LoongArch64)
- Creating distribution packages (TAR.GZ, DEB, RPM, MSI, DMG)
- Building and publishing Docker images
- Creating GitHub releases with artifacts

### Docker Image Tags

Docker images are tagged based on the release type:

| Release Type | Docker Tags |
|--------------|-------------|
| Stable | `latest`, `<version>` (e.g., `1.0.0`) |
| Weekly | `weekly`, `<version>` |
| Nightly | `nightly`, `<version>` |
| Monthly | `monthly`, `<version>` |

**Example**: A stable release version `1.2.3` creates:
- `ghcr.io/yourorg/biubo-rust:latest`
- `ghcr.io/yourorg/biubo-rust:1.2.3`
- `yourusername/biubo-waf:latest` (if Docker Hub is configured)
- `yourusername/biubo-waf:1.2.3` (if Docker Hub is configured)

---

## Additional Resources

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Docker Hub Access Tokens](https://docs.docker.com/docker-hub/access-tokens/)
- [GitHub Container Registry Documentation](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry)

---

**Questions or Issues?**

If you encounter problems with CI/CD configuration:
1. Check the [Troubleshooting](#troubleshooting) section above
2. Review workflow logs in the **Actions** tab
3. Open a GitHub Discussion or Issue with relevant log excerpts

---

*Last updated: 2024 - This document is maintained as part of the Biubo WAF project.*
