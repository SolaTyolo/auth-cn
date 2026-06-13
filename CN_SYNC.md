# CN 分支同步指南

本仓库维护两个长期分支：

| 分支 | 用途 |
|------|------|
| `master` | [supabase/auth](https://github.com/supabase/auth) 的 upstream 镜像，不含中国区代码 |
| `cn` | 生产分支：`master` + 中国接入（OAuth、短信、验证码） |

**原则：** 变更只能单向流动：

```
supabase/auth  →  master  →  cn
```

禁止将 `cn` merge 进 `master`。

---

## 分支结构

```
upstream (supabase/auth)
       │
       ▼
    master          ← 仅同步 upstream，无 CN commit
       │
       ▼ merge
      cn             ← 从此分支部署
       ▲
       │ PR
 feature/cn-*        ← 新 CN 功能开发
```

---

## CN 代码位置

中国区能力单独隔离，以降低与 upstream 合并时的冲突：

| 模块 | 代码位置 | 接入方式 |
|------|----------|----------|
| OAuth（Line、抖音、微信、企业微信） | `internal/api/provider/*.go` | `init()` → `provider/cn_registry.go` → `external.go` 的 `default` 分支 |
| SMS（腾讯云、阿里云） | `internal/api/sms_provider/*.go` | `init()` → `sms_provider/cn_registry.go` → `sms_provider.go` 的 `default` 分支 |
| 验证码（腾讯云） | `internal/security/cn_captcha.go` | `internal/security/captcha.go` 的 `default` 分支 |
| Settings 开关 | `internal/api/cn_settings.go` | 嵌入 `internal/api/settings.go` |
| 配置结构体 | `internal/conf/configuration.go` | 仅在末尾追加字段 |

### 新增 CN Provider

1. 在 `internal/api/provider/` 或 `internal/api/sms_provider/` 下**新建文件**实现 provider。
2. 在该文件的 `init()` 中调用 `RegisterCNOAuthProvider` 或 `RegisterCNSMSProvider` 注册（**不要**往 upstream 的 switch 里加 case）。
3. 在 `internal/conf/configuration.go` 补充配置结构体和环境变量。
4. 编写 provider 测试及 `*_registry_test.go`。
5. 向 `cn` 提 PR（不要向 `master` 提）。

---

## 同步 upstream → master

手动执行：

```bash
git remote add upstream https://github.com/supabase/auth.git   # 只需一次
git fetch upstream --tags

git checkout master
git merge --ff-only upstream/master   # 或: git merge upstream/master
git push origin master
```

upstream 同步为**纯手动**操作，无自动化 workflow。

---

## 同步 master → cn

`master` 更新后：

```bash
git checkout cn
git pull origin cn
git merge master -m "chore(cn): sync upstream vX.Y.Z"
make test
git push origin cn
```

也可在 GitHub Actions 中手动运行 [`.github/workflows/sync-cn.yml`](.github/workflows/sync-cn.yml)，自动创建 PR。

### 合并冲突处理清单

若发生冲突，按以下顺序处理：

1. `internal/api/external.go` — 保留 upstream 的 case；确保 `default` 中仍有 `provider.ResolveCNOAuthProvider`
2. `internal/api/sms_provider/sms_provider.go` — 保留 upstream 的 case；确保 `default` 中仍有 `ResolveCNSMSProvider`
3. `internal/security/captcha.go` — 以 upstream 结构为准；保留 CN 验证码的 `default` 钩子
4. `internal/conf/configuration.go` — 同时保留 upstream 与 CN 配置字段
5. `example.env` — 合并 CN 环境变量块与 upstream 新增项

建议开启 rerere，记住重复冲突的解法：

```bash
git config rerere.enabled true
```

---

## 开发流程

```bash
git checkout cn && git pull
git checkout -b feature/cn-my-feature

# ... 开发与测试 ...
make test

git push -u origin feature/cn-my-feature
# 开 PR → cn
```

---

## 发布与镜像

CN 版本单独打 tag，与 upstream 区分：

```bash
git tag cn-v2.189.0 cn
git push origin cn-v2.189.0
```

从 `cn` 分支构建并部署 Docker 镜像。

镜像推送到腾讯云容器镜像服务（TCR），workflow 见 [`.github/workflows/publish.yml`](.github/workflows/publish.yml)。

需在 GitHub 仓库 Secrets 中配置：

| Secret | 示例 | 说明 |
|--------|------|------|
| `TCR_REGISTRY` | `ccr.ccs.tencentyun.com` | TCR 镜像仓库域名 |
| `TCR_NAMESPACE` | `treelab` | 命名空间 |
| `TCR_USERNAME` | `100012345678` | TCR 登录用户名 |
| `TCR_PASSWORD` | *（TCR 控制台获取）* | TCR 登录密码 / 访问凭证 |

发布镜像地址：`{TCR_REGISTRY}/{TCR_NAMESPACE}/auth-cn:vX.Y.Z`

---

## 同步后冒烟测试

每次 `master → cn` 合并后检查：

- [ ] `make test` 通过
- [ ] 微信 / 抖音 / Line OAuth 登录
- [ ] 腾讯云 / 阿里云短信 OTP 发送
- [ ] 腾讯云验证码校验
- [ ] `GET /settings` 返回 CN provider 开关

---

## 常见问题

### merge master 进 cn 会让 commit 消失吗？

不会。Merge 只会追加历史，CN 相关 commit 都还在 `cn` 上。

### 可以把 cn rebase 到 master 上吗？

不建议对已部署的分支使用 rebase，请用 merge。

### CN provider 要不要贡献给 upstream？

除非 Supabase 官方接受，否则继续放在 `cn` 分支，通过 provider/SMS registry 和 `internal/security/cn_captcha.go` 维护即可。
