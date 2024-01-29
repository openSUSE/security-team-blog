# security-team-blog

Sources for the blog at https://security.opensuse.org.

## Local development

### Podman container

```./run-podman```

This will run Jekyll in a Podman container, with the checked out git repository mounted inside. You can access this instance via `http://127.0.0.1:4000`.

Jekyll will reload itself on the fly whenever you make changes.

### Manual installation

- Install jekyll:
  ```
  sudo zypper in ruby ruby-devel
  bundle config set path 'vendor/bundle'
  bundle install
  ```
- Serve page locally for testing: 
  - `bundle exec jekyll serve`
  - then check `http://localhost:4000`
- Add new content to `_posts`, examples: https://jekyllrb.com/docs/posts/
