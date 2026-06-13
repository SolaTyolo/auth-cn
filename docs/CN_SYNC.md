# CN Branch Sync Guide

This fork maintains two long-lived branches:

| Branch | Purpose |
|--------|---------|
| `master` | Upstream mirror of [supabase/auth](https://github.com/supabase/auth). No CN-specific code. |
| `cn` | Production branch: `master` + China integrations (OAuth, SMS, captcha). |

**Rule:** changes flow in one direction only:

```
supabase/auth  →  master  →  cn
```

Never merge `cn` into `master`.

---

## Branch layout

```
upstream (supabase/auth)
       │
       ▼
    master          ← sync only, no CN commits
       │
       ▼ merge
      cn             ← deploy from here
       ▲
       │ PR
 feature/cn-*        ← new CN work
```

---

## Where CN code lives

CN integrations are isolated to reduce merge conflicts with upstream:

| Area | Location | Hot-path hook |
|------|----------|---------------|
| OAuth (Line, Douyin, WeChat, WeChat Work) | `internal/api/provider/*.go` | `init()` → `provider/cn_registry.go` → `external.go` `default` case |
| SMS (Tencent, Aliyun) | `internal/api/sms_provider/*.go` | `init()` → `sms_provider/cn_registry.go` → `sms_provider.go` `default` case |
| Captcha (Tencent) | `internal/security/cn_captcha.go` | `internal/security/captcha.go` `default` case |
| Settings flags | `internal/api/cn_settings.go` | embedded in `internal/api/settings.go` |
| Config structs | `internal/conf/configuration.go` | append-only fields |

### Adding a new CN provider

1. Implement the provider in a **new file** under `internal/api/provider/` or `internal/api/sms_provider/`.
2. Register it in that file's `init()` via `RegisterCNOAuthProvider` or `RegisterCNSMSProvider` (do **not** add cases to upstream switch blocks).
3. Add config structs and env vars in `internal/conf/configuration.go`.
4. Add tests alongside the provider and in `*_registry_test.go`.
5. Open a PR into `cn` (not `master`).

---

## Sync upstream → master

### Manual

```bash
git remote add upstream https://github.com/supabase/auth.git   # once
git fetch upstream --tags

git checkout master
git merge --ff-only upstream/master   # or: git merge upstream/master
git push origin master
```

### Automated

GitHub Actions workflow [`.github/workflows/sync-upstream.yml`](../.github/workflows/sync-upstream.yml) runs weekly (and on demand). It opens a PR to `master` when upstream has new commits.

---

## Sync master → cn

After `master` is updated:

```bash
git checkout cn
git pull origin cn
git merge master -m "chore(cn): sync upstream vX.Y.Z"
make test
git push origin cn
```

Or use the [`.github/workflows/sync-cn.yml`](../.github/workflows/sync-cn.yml) workflow to open a PR automatically.

### Merge conflict checklist

If conflicts occur, resolve in this order:

1. `internal/api/external.go` — keep upstream cases; ensure `provider.ResolveCNOAuthProvider` remains in `default`
2. `internal/api/sms_provider/sms_provider.go` — keep upstream cases; ensure `ResolveCNSMSProvider` remains in `default`
3. `internal/security/captcha.go` — prefer upstream structure; keep CN captcha hooks in `default`
4. `internal/conf/configuration.go` — keep both upstream and CN config fields
5. `example.env` — merge CN env block with upstream additions

Enable rerere to remember repeated resolutions:

```bash
git config rerere.enabled true
```

---

## Development workflow

```bash
git checkout cn && git pull
git checkout -b feature/cn-my-feature

# ... implement & test ...
make test

git push -u origin feature/cn-my-feature
# Open PR → cn
```

---

## Release tagging

Tag CN releases separately from upstream:

```bash
git tag cn-v2.189.0 cn
git push origin cn-v2.189.0
```

Build and deploy Docker images from the `cn` branch.

---

## Post-sync smoke tests

After every `master → cn` merge:

- [ ] `make test` passes
- [ ] WeChat / Douyin / Line OAuth login
- [ ] Tencent / Aliyun SMS OTP send
- [ ] Tencent captcha verification
- [ ] `GET /settings` returns CN provider flags

---

## FAQ

### Does merging master into cn delete commits?

No. Merge only adds history. All CN commits remain on `cn`.

### Can I rebase cn onto master?

Not recommended for a deployed branch. Use merge instead.

### Should I contribute CN providers upstream?

Only if Supabase accepts them. Until then, keep them in `cn` via provider/SMS registries and `internal/security/cn_captcha.go`.
