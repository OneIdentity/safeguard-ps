---
name: build-and-release
description: Use when working on Azure Pipelines builds, version stamping, signing, publishing, or release artifacts for safeguard-ps.
---

# Build and Release

Use this skill when you need to reproduce CI locally, reason about version numbers, update Azure Pipelines, or troubleshoot how `safeguard-ps` is signed and published.

## 1. Pipeline architecture

### Entry point and shared files

The release flow is driven by Azure Pipelines, not GitHub Actions.

- `build.yml` -- only pipeline entry point
- `pipeline-templates/global-variables.yml` -- shared variables such as the base semantic version and publish flags
- `pipeline-templates/build-windows-steps.yml` -- Windows validation and module packaging steps
- `pipeline-templates/build-linux-steps.yml` -- Linux validation plus Docker image build steps
- `pipeline-templates/versionnumber.ps1` -- Windows version variable derivation
- `pipeline-templates/versionnumber.sh` -- Linux version variable derivation
- `pipeline-templates/install-forpipeline.ps1` -- manifest stamping, local install into `PSModulePath`, catalog creation, and strict linting

### Triggers

`build.yml` runs for:

- pushes to `main`, `master`, and `release-*`
- tags matching `v*`
- PRs targeting `main`, `master`, and `release-*`

It skips docs-only changes under these path exclusions:

- `**/*.md`
- `LICENSE`
- `samples`
- `.github`

### Job layout

There are four top-level jobs, no YAML `stages:` block:

1. `PRValidation_Windows`
   - condition: `Build.Reason == PullRequest`
   - agent: `windows-latest`
   - runs `build-windows-steps.yml`
2. `PRValidation_Linux`
   - condition: `Build.Reason == PullRequest`
   - agent: `ubuntu-latest`
   - runs `build-linux-steps.yml`
3. `BuildAndPublish_Windows`
   - condition: not pull request
   - agent: `windows-latest`
   - runs `build-windows-steps.yml`
   - then signs and publishes the PowerShell module and creates a GitHub release asset
4. `BuildAndPublish_Linux`
   - condition: not pull request
   - agent: `ubuntu-latest`
   - runs `build-linux-steps.yml`
   - then pushes Docker images when `shouldPublishDocker` is true

### What the step templates actually do

`build-windows-steps.yml`:

- computes `VersionString`, `PrereleaseSuffix`, and `ReleaseTag` with `versionnumber.ps1`
- finds a writable PowerShell module directory from `PSModulePath`
- runs `install-forpipeline.ps1 <ModuleDir> <VersionString> <IsPrerelease> <PrereleaseSuffix>`
- imports `safeguard-ps` to prove the staged module loads
- parses every `src\*.ps1`, `src\*.psm1`, and `src\*.psd1` file under Windows PowerShell 5.1
- imports the module again under Windows PowerShell 5.1 to catch compatibility regressions

`build-linux-steps.yml`:

- computes the same version variables with `versionnumber.sh`
- locates a usable module directory from `PSModulePath`
- runs the same `install-forpipeline.ps1` stamping/install/lint flow under PowerShell
- builds Docker images for `ubuntu`, `azurelinux`, and `alpine`
- tags the Alpine image as `oneidentity/safeguard-ps:latest`

## 2. Version strategy

### Source of truth

The base released version lives in `pipeline-templates/global-variables.yml`:

```yaml
variables:
  - name: version
    value: "8.4.3"
```

The source manifest mirrors that base version with a `99999` build placeholder:

```powershell
ModuleVersion = '8.4.3.99999'
```

CI replaces the `99999` portion (and adds the prerelease suffix) at build time -- do not hand-edit `99999` for normal development work. The `<major>.<minor>.<patch>` portion is hand-bumped between release cycles (see "Bumping the version" below).

### Bumping the version for the next prerelease cycle

After cutting a release tag (e.g. `v8.4.2`), main keeps producing prereleases against that same base version (`dev/v8.4.2-preNNNNNN`) until the base is bumped. To start a new cycle (e.g. moving to 8.4.3 prereleases so a future `v8.4.3` tag can ship):

1. Edit `pipeline-templates/global-variables.yml` -- update the `version` value (e.g. `"8.4.2"` -> `"8.4.3"`).
2. Edit `src/safeguard-ps.psd1` -- update `ModuleVersion` to match (e.g. `'8.4.2.99999'` -> `'8.4.3.99999'`). Keep the `.99999` placeholder.
3. Commit both changes together. Suggested message: `Bump version to <new> for next prerelease cycle`.
4. The next CI build off main will produce `dev/v<new>-preNNNNNN` prereleases. When ready to ship, push a `v<new>` tag and the tag build will publish a non-prerelease release.

The two files must stay in sync -- `install-forpipeline.ps1` substitutes `<major>.<minor>.99999` based on the pipeline `version` variable, so a mismatched manifest will fail stamping.

### Tag builds

Tag builds are detected when `Build.SourceBranch` starts with `refs/tags/`.

`versionnumber.ps1` and `versionnumber.sh` both require tags to match:

```text
v<major>.<minor>.<patch>
```

For a valid tag build:

- `VersionString` becomes the tag without the leading `v`
- `PrereleaseSuffix` becomes empty
- `ReleaseTag` stays equal to the Git tag, for example `v8.3.0`
- `isPrerelease` is false
- `shouldPublishDocker` is true

### Non-tag builds

For branch and PR builds:

- `VersionString` stays at the base version from `global-variables.yml`
- `BuildNumber` is computed as `Build.BuildId - 250000`
- `PrereleaseSuffix` becomes `pre<BuildNumber>`
- `ReleaseTag` becomes `dev/v<version>-pre<BuildNumber>`
- `isPrerelease` is true
- `shouldPublishDocker` is false

Example from the scripts:

```text
version     = 8.4.3
Build.BuildId = 367659
BuildNumber = 117659
PrereleaseSuffix = pre117659
ReleaseTag = dev/v8.4.3-pre117659
```

### Manifest stamping behavior

`install-forpipeline.ps1` converts the source manifest to the build version by:

1. replacing `<major>.<minor>.99999` with `VersionString`
2. replacing `Prerelease = 'pre'` with the computed prerelease suffix on non-tag builds
3. commenting out the prerelease line on release builds
4. creating `src\safeguard-ps.cat` on Windows with `New-FileCatalog`
5. installing the stamped module into the selected `PSModulePath`
6. running `./Invoke-PsLint.ps1 -Strict`

## 3. Build commands

### Fast local reproduction

The repo has no compile step; the build is a staged module install from source.

```powershell
Remove-Module safeguard-ps -ErrorAction SilentlyContinue
./cleanup-local.ps1
./install-local.ps1
Import-Module safeguard-ps
Get-SafeguardCommand Get Asset
```

If you want local linting during install:

```powershell
./install-local.ps1 -WithLinting
./Invoke-PsLint.ps1 -Strict
```

### Reproducing the pipeline install logic

To mimic what CI does on Windows:

```powershell
$moduleDir = (($env:PSModulePath -split ';') | Where-Object { Test-Path $_ })[0]
./pipeline-templates/versionnumber.ps1 8.3.0 102745 feature-branch False
./pipeline-templates/install-forpipeline.ps1 $moduleDir 8.3.0 $true pre245
Import-Module safeguard-ps -Force
```

To mimic the Linux template logic from PowerShell or `pwsh`:

```powershell
$moduleDir = (($env:PSModulePath.Split([System.IO.Path]::PathSeparator)) | Where-Object { Test-Path $_ })[0]
./pipeline-templates/install-forpipeline.ps1 $moduleDir 8.3.0 $true pre245
```

To reproduce the Docker portion locally:

```powershell
bash ./docker/build-docker.sh ubuntu 8.3.0
bash ./docker/build-docker.sh azurelinux 8.3.0
bash ./docker/build-docker.sh alpine 8.3.0
```

### Windows compatibility checks worth preserving

The Windows pipeline explicitly validates:

- import under PowerShell 7+
- parse success for all `src` files under Windows PowerShell 5.1
- import under Windows PowerShell 5.1

If you touch `src/`, keep those checks mentally in scope even for seemingly small syntax changes.

## 4. Publishing targets

### PowerShell Gallery

The Windows publish job retrieves `PowerShellGalleryApiKey` and runs:

```powershell
Publish-Module -Name safeguard-ps -NuGetApiKey "$(PowerShellGalleryApiKey)" -Verbose -SkipAutomaticTags -Force
```

The published artifact is the staged module that `install-forpipeline.ps1` installed into the agent's module path.

### Catalog signing

The module is signed before publish by:

1. downloading and silently installing SSL.com's `eSignerCKA`
2. loading the code-signing certificate into `Cert:\CurrentUser\My`
3. locating the generated `safeguard-ps.cat`
4. finding the x86 `signtool.exe` under `C:\Program Files (x86)\Windows Kits`
5. signing with SHA-256 and timestamping via `http://ts.ssl.com`
6. verifying the result with `Get-AuthenticodeSignature`

This pipeline signs the catalog file, not every source file individually.

### GitHub release artifact

After publish, the Windows job zips the installed module directory into:

```text
safeguard-ps-$(VersionString).zip
```

Then `GitHubRelease@1` creates a release in `OneIdentity/safeguard-ps` using `$(ReleaseTag)` and uploads the zip as the release asset.

### Docker Hub

The Linux publish job pushes:

- `oneidentity/safeguard-ps:$(VersionString)-ubuntu`
- `oneidentity/safeguard-ps:$(VersionString)-azurelinux`
- `oneidentity/safeguard-ps:$(VersionString)-alpine`
- `oneidentity/safeguard-ps:latest`

Docker pushes only happen when `shouldPublishDocker` is true, which today means tag builds only.

## 5. Service connections / secrets required

### Azure Key Vault and service connections

`build.yml` depends on these Azure DevOps connections:

- `SafeguardOpenSource`
  - Key Vault: `SafeguardBuildSecrets`
  - secrets: `PowerShellGalleryApiKey`, `DockerHubAccessToken`, `DockerHubPassword`
- `OneIdentity.Infrastructure.SPPCodeSigning`
  - Key Vault: `SPPCodeSigning`
  - secrets: `SPPCodeSigning-Password`, `SPPCodeSigning-TotpPrivateKey`

### Other external connections

- GitHub service connection: `PangaeaBuild-GitHub`
- Docker Hub credentials are used by `docker login`
- SSL.com eSigner account: `ssl.oid.safeguardpp@groups.quest.com`

### Operational gotchas

- PRs from forks cannot access secrets, so signing and publish steps only belong in non-PR jobs.
- `install-forpipeline.ps1` always runs strict linting; pipeline failures there are usually real release blockers.
- If signing fails, check both Key Vault secret retrieval and whether `eSignerCKATool.exe load` populated `Cert:\CurrentUser\My`.
- If a release version looks wrong, inspect `global-variables.yml`, the incoming Git tag, and the `VersionString`/`PrereleaseSuffix` variables emitted by the versionnumber scripts.
