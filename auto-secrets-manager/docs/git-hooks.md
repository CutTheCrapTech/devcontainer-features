# Git Hooks for Auto-Secrets Manager

This is the most performant setup, as it avoids the overhead of shell integration and triggers secrets refresh automatically when switching branches.

## Option 1: Repository-Specific Setup (Recommended)

Use this for individual projects where you want auto-secrets management:

```bash
# Set hooks directory for this repository only
git config --local core.hooksPath /usr/local/share/auto-secrets/hooks/
```

**Pros:** Only affects the current repository, safe for mixed workflows
**Cons:** Must be set up per repository

## Option 2: User-Wide Setup

Use this if you want auto-secrets for all your repositories:

```bash
# Set hooks directory for all repositories for the current user
git config --global core.hooksPath /usr/local/share/auto-secrets/hooks/
```

**Pros:** One-time setup, works across all repositories
**Cons:** Affects ALL repositories, may interfere with other projects

## Option 3: System-Wide Setup (Not Recommended)

```bash
# Set hooks directory for all users on the system (requires admin privileges)
git config --system core.hooksPath /usr/local/share/auto-secrets/hooks/
```

**⚠️ Warning:** This affects every user and repository on the system. Only use in dedicated development environments.

## Option 4: Copy Individual Hook (Alternative)

If you prefer not to change the hooks directory:

```bash
# Copy the specific hook to your repository
cp /usr/local/share/auto-secrets/hooks/post-checkout $YOUR_REPO/.git/hooks/
chmod +x $YOUR_REPO/.git/hooks/post-checkout
```

**Use this when:** You already have other git hooks or want more granular control.

## Option 5: Manual Integration

If you have existing git hooks, you can integrate auto-secrets by adding this line to your existing `post-checkout` hook:

```bash
# Add to existing .git/hooks/post-checkout
/usr/local/share/auto-secrets/hooks/post-checkout "$@"
```

## Verification

Test your setup by switching branches:

```bash
git checkout different-branch
# Should automatically refresh secrets for the new branch
```

## Troubleshooting

- **Hook not executing?** Check permissions: `chmod +x /usr/local/share/auto-secrets/hooks/*`
- **Still using shell integration?** Hooks take precedence and are more efficient
- **Multiple hooks needed?** Only `post-checkout` is required for branch switching
