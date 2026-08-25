FROM registry.opensuse.org/opensuse/leap:16.0

RUN zypper ref
RUN zypper install -y \
	ruby \
	ruby-devel
RUN zypper install -y -t pattern devel_C_C++

WORKDIR /work

ENTRYPOINT bundle config set path 'vendor/bundle' && \
	bundle install && \
	bundle exec jekyll serve --host=0.0.0.0 --future
