FROM registry.opensuse.org/opensuse/leap:16.0

RUN zypper --non-interactive refresh
RUN zypper --non-interactive install --no-recommends \
	ruby \
	ruby-devel \
	gcc \
	gcc-c++ \
	make \
	tar && \
	zypper clean -a && \
	rm -rf /var/cache/zypp/* /tmp/*

WORKDIR /work

ENTRYPOINT bundle config set path 'vendor/bundle' && \
	bundle install && \
	bundle exec jekyll serve --host=0.0.0.0 --future
