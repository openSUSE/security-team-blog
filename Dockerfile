FROM registry.opensuse.org/opensuse/leap:15.5

RUN zypper ref
RUN zypper install -y \
	ruby \
	ruby-devel
RUN zypper install -y -t pattern devel_C_C++

# Required for opensuse/leap:15.5 (not Tumbleweed):
RUN gem install bundler -v 2.3.27 --no-user-install && \
	ln -s /usr/bin/bundle.ruby2.5 /usr/bin/bundle

WORKDIR /work

ENTRYPOINT bundle config set path 'vendor/bundle' && \
	bundle install && \
	bundle exec jekyll serve --host=0.0.0.0
