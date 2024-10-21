FROM registry.opensuse.org/opensuse/leap:15.6

RUN zypper ref
RUN zypper install -y \
	ruby \
	ruby-devel
RUN zypper install -y -t pattern devel_C_C++

# Required for openSUSE Leap 15.5 and 15.6
RUN gem install bundler -v 2.3.27 --no-user-install && \
	ln -s /usr/bin/bundle.ruby2.5 /usr/bin/bundle

WORKDIR /work

ENTRYPOINT bundle config set path 'vendor/bundle' && \
	bundle install && \
	bundle exec jekyll serve --host=0.0.0.0
