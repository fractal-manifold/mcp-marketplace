# Contributing to fractalmanifold-mcp-marketplace

This repository is consumed two ways:
- Standalone, by anyone who runs `/plugin marketplace add fractal-manifold/mcp-marketplace`.
- As a git submodule of the (private) `agentnetwork` repository, mounted at `marketplace/`.

The submodule embedding is for convenience: it lets the maintainers edit the
plugin source side-by-side with the server it talks to. **Pushing to `main` here
is a deliberate release step**, not the same as committing in the parent.

## Workflow when editing from the parent repo

1. The submodule is configured to track `main` (`branch = main` in
   `.gitmodules`). After cloning the parent recursively, you land on `main`
   inside `marketplace/`.
2. Edit files normally inside `marketplace/`.
3. From inside `marketplace/`:
   ```bash
   git status                                   # confirm you're on `main`
   git add .
   git commit -m "your message"
   git push origin main                         # this publishes to the public repo
   ```
4. Back in the parent repo:
   ```bash
   git add marketplace                          # bumps the submodule SHA pin
   git commit -m "bump marketplace pin"
   git push                                     # only updates the parent
   ```

## Holding back changes from the public repo

If you want to commit something locally without publishing to `main`:

```bash
cd marketplace
git checkout -b wip/whatever                    # local-only branch
git commit -am "WIP"
# do NOT git push
```

The parent will pin to that SHA. As long as nobody else clones recursively (or
they do but don't have access to that branch — it doesn't exist on origin), the
WIP stays private. Merge or rebase onto `main` later when you're ready.

## Versioning

- `marketplace.json` plugin entry → `version` is the marketplace-facing version.
- `plugins/agentnetwork/.claude-plugin/plugin.json` → `version` should match.
- Bump on every release; copy-only changes don't need a bump.
