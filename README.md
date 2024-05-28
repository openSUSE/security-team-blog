# security-team-blog

Sources for the blog at https://security.opensuse.org.

## Local development

### Podman container

```./run-podman```

This will run Jekyll in a Podman container, with the checked out git repository mounted inside. You can access this instance via `http://127.0.0.1:4000`.

Jekyll will reload itself on the fly whenever you make changes.

### Using a dedicated environment

rvm is a tool allows people to have different ruby versions with project
specific environments on their systems. The collection of ruby gems (the third
party libraries in ruby), is called gemset in rvm slang.

Installing rvm (https://rvm.io/rvm/install) is easy:

```
$ gpg --keyserver keyserver.ubuntu.com --recv-keys 409B6B1796C275462A1703113804BB82D39DC0E3 7D2BAF1CF37B13E2069D6956105BD0E739499BDB
$ curl -sSL https://get.rvm.io | bash
```

Now it's good time to install a ruby compiler, not the one provided with our
distro.

```
$ rvm install ruby-3.2.2

... let the system compile here ...

$ rvm --default use 3.2.2
```

The last command tell we want to use newly installed compiler as a default. Since rvm script is run in shell init scripts, if you need to use openSUSE provided ruby compiler you have to issue this command.

```
$ rvm use system
```

Now let's enter in the blog directory and create a gemset for jekyll.

```
$ cd security-team-blog
$ rvm use --create --ruby-version 3.2.2@jekyll
```

In the current directory rvm created two hidden files, containing the ruby
version to use and the gemset. Everytime you enter in the blog directory rvm
switch to the correct environment:

```
-rw-r--r-- 1 thesp0nge users    7 May 23 17:09 .ruby-gemset
-rw-r--r-- 1 thesp0nge users   11 May 23 17:09 .ruby-version
```


First step here is to install bundler gem. Bundler is the gem managing gemset bundles.

```
$ gem install bundler
```

Now we install all gems we need that are listed in Gemfile file.

```
$ bundle install
```

Now with the following command you can start jekyll:

```
$ bundle exec jekyll serve
```

### Manual installation

- Install jekyll:
  ```
  sudo zypper in ruby ruby-devel
  sudo zypper in -t pattern devel_C_C++
  bundle config set path 'vendor/bundle'
  bundle install
  ```
- Serve page locally for testing:
  - `bundle exec jekyll serve`
  - then check `http://localhost:4000`
- Add new content to `_posts`, examples: https://jekyllrb.com/docs/posts/
