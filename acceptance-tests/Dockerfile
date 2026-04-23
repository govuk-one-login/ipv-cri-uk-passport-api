# https://hub.docker.com/layers/library/gradle/jdk25-corretto/
FROM gradle@sha256:93b734fe2aa8a03745c8575c45bfaf89fcf86848e6a8512dfa0ba13b9133d6ba AS base_image
# NOTE : There are two targets in this dockerfile traffic_test_image and ac_test_image
# The following will allow you to test building the amd64 images on an arm64 mac
# From the root dir - ipv-cri-uk-passport-api
# DOCKER_DEFAULT_PLATFORM=linux/amd64 docker build -f acceptance-tests/Dockerfile --target ac_test_image --tag 'passport-ac-test-image' .
# or
# DOCKER_DEFAULT_PLATFORM=linux/amd64 docker build -f acceptance-tests/Dockerfile --target traffic_test_image --tag 'passport-traffic-test-image' .

WORKDIR /home/gradle/cri

# AWS CLI & AWS GPG KEY
COPY "acceptance-tests/public-keys/aws-cli.gpg" "aws-cli.gpg"
ADD "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" "awscliv2.zip"
ADD "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip.sig" "awscliv2.zip.sig"

# Googles public key
COPY "acceptance-tests/public-keys/google-linux-signing-key.pub" "google-linux-signing-key.pub"

# NOTE : Chrome not available for arm64 linux currently and we want to use chrome not chromium
# 1) Adds Googles gpg key, then sets up the Google Chrome RPM repo, then installs chrome from the repo
# 2) Import the aws-cli.gpg key, verifies the awscliv2.zip signature and installs the aws-cli
# 3) Remove the downloaded files
# 4) Clear the dnf cache to avoid bloating the image any further

# heredoc
RUN <<EOF
    set -e
    cat > /etc/yum.repos.d/google-chrome.repo <<'REPO'
[google-chrome]
name=google-chrome
baseurl=http://dl.google.com/linux/chrome/rpm/stable/x86_64
enabled=1
gpgcheck=1
REPO
    dnf install -y --allowerasing --setopt=install_weak_deps=False jq gnupg2

    rpm --import google-linux-signing-key.pub
    dnf install -y --setopt=install_weak_deps=False google-chrome-stable
    rm ./google-linux-signing-key.pub

    gpg --batch --no-tty --import aws-cli.gpg
    gpg --batch --no-tty --verify awscliv2.zip.sig awscliv2.zip
    unzip -q awscliv2.zip && ./aws/install
    rm -rf ./aws ./awscliv2.zip ./awscliv2.zip.sig ./aws-cli.gpg

    rm -rf /var/cache/dnf /var/cache/yum /var/log/*
EOF

# Package just the contents of acceptance-tests
COPY acceptance-tests acceptance-tests
RUN mv acceptance-tests/run-tests.sh /run-tests.sh

# Package the top level gradle files so ac tests can run standalone in the container
COPY gradle.properties .
COPY gradle gradle
COPY settings.gradle .

# Cache the java deps, gradle build within the image
ENV AC_TEST_ONLY=true
RUN gradle :acceptance-tests:dependencies :acceptance-tests:assemble :acceptance-tests:testClasses --no-daemon \
    && (gradle cucumber --no-watch-fs --no-daemon -P tags="@nonexistent" || true)

FROM base_image AS traffic_test_image
ENV TRAFFIC_TEST=true
ENTRYPOINT ["/run-tests.sh"]

FROM base_image AS ac_test_image
ENTRYPOINT ["/run-tests.sh"]
