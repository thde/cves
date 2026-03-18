# cves

RSS bridge for GitHub Security Advisories. Subscribe to any GitHub repository's published advisories in your RSS reader.

## Usage

```
GET /v1/github/{owner}/{repo}
```

Returns an RSS 2.0 feed by default. Pass `Accept: text/html` for an HTML view.

**Query parameters**

| Parameter  | Description                                                           |
| ---------- | --------------------------------------------------------------------- |
| `v`        | Filter advisories affecting a specific version (semver, e.g. `2.3.4`) |
| `severity` | Filter by severity: `critical`, `high`, `medium`, or `low`            |

**Example**

```
/v1/github/argoproj/argo-cd
/v1/github/argoproj/argo-cd?v=2.9.0&severity=critical
```

## Configuration

| Environment variable | Default         | Description                                                     |
| -------------------- | --------------- | --------------------------------------------------------------- |
| `GITHUB_TOKEN`       | —               | GitHub personal access token (recommended to avoid rate limits) |
| `ADDR`               | `:8080`         | Listen address                                                  |
| `PORT`               | `8080`          | Port (ignored when `ADDR` is set)                               |
| `CACHE_DIR`          | `~/.cache/cves` | Directory for the on-disk advisory cache                        |

## Running

```sh
go run .
```
