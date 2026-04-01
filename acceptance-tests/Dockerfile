# gradle:9.4.1-jdk25
FROM gradle@sha256:c81867d40732e0d1af0bbce85eae6c61d326320cacec2d1bbf011d68ace184a8 AS base_image
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
# 1) Adds Googles gpg key, then sets up the Google Chrome Debian package repo, then installs chrome from the package repo
# 2) Import the aws-cli.gpg key, verifies the awscliv2.zip signature and installs the aws-cli
# 3) Then remove all the downloaded files and apt cache to avoid bloating the image any further

RUN apt-get update \
    && apt-get install -y --no-install-recommends jq gnupg \
    && gpg --dearmor < google-linux-signing-key.pub > /usr/share/keyrings/google-chrome.gpg \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-chrome.gpg] http://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends google-chrome-stable \
    && rm ./google-linux-signing-key.pub \
    && gpg --import aws-cli.gpg \
    && gpg --verify awscliv2.zip.sig awscliv2.zip \
    && unzip awscliv2.zip && ./aws/install \
    && rm ./awscliv2.zip \
    && rm ./awscliv2.zip.sig \
    && rm ./aws-cli.gpg \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Package just the contents of acceptance-tests
COPY acceptance-tests acceptance-tests

# Package the top level gradle files so ac tests can run standalone in the container
COPY gradle.properties .
COPY gradle gradle
COPY settings.gradle .

# Cache the java deps, gradle build and webdriver fetch within the image
ENV AC_TEST_ONLY=true
RUN gradle :acceptance-tests:dependencies :acceptance-tests:assemble :acceptance-tests:testClasses --no-daemon \
    && (gradle cucumber --no-watch-fs --no-daemon -P tags="@nonexistent" || true)

FROM base_image AS traffic_test_image
RUN mv acceptance-tests/traffic-tests/run-tests.sh /run-tests.sh
ENTRYPOINT ["/run-tests.sh"]

FROM base_image AS ac_test_image
RUN mv acceptance-tests/run-tests.sh /run-tests.sh
ENTRYPOINT ["/run-tests.sh"]
