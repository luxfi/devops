
# luxup AWS recipes (advanced)

These recipes wrap the upstream `avalancheup-aws` provisioner so it deploys
**`luxd`** (`github.com/luxfi/node`) instead of upstream `avalanchego`. The
provisioner CLI keeps its upstream name because Lux does not yet ship an
equivalent (`luxup-aws`) — **flagged for follow-up migration to a native
`luxup-aws` binary**. Where flag names below still read `--upload-artifacts-avalanchego-local-bin`,
they accept the `luxd` binary unchanged.

## Step 1: Install `avalancheup` (upstream provisioner)

To download from release, visit https://github.com/ava-labs/avalanche-ops/releases.

To compile from source:

```bash
# if you don't have rust on your local
curl -sSf https://sh.rustup.rs | sh -s -- -y \
&& . ${HOME}/.cargo/env \
&& rustc --version && cargo --version \
&& which rustc && which cargo
```

```bash
# to build binaries
./scripts/build.release.sh
```

Make sure you have access to the following CLI:

```bash
avalancheup-aws -h
```

## Step 2: Install artifacts on your local machine

In order to provision a Lux node, you need the software compiled for the
remote machine's OS and architecture (e.g., if your server runs linux, then
you need provide linux binaries to `avalancheup` commands).

For instance, to download the latest `luxd` release:

```bash
# https://github.com/luxfi/node/releases
VERSION=1.23.23
DOWNLOAD_URL=https://github.com/luxfi/node/releases/download/
rm -rf /tmp/luxd.tar.gz /tmp/luxd-v${VERSION}
curl -L ${DOWNLOAD_URL}/v${VERSION}/luxd-linux-amd64-v${VERSION}.tar.gz -o /tmp/luxd.tar.gz
tar xzvf /tmp/luxd.tar.gz -C /tmp
find /tmp/luxd-v${VERSION}
```

To cross-compile locally, run something like:

```bash
# https://github.com/FiloSottile/homebrew-musl-cross
brew install FiloSottile/musl-cross/musl-cross
ln -s /usr/local/opt/musl-cross/bin/x86_64-linux-musl-gcc /usr/local/bin/musl-gcc

# -ldflags=-w to turn off DWARF debugging information
# -ldflags=-s to disable generation of the Go symbol table
rm -rf ${HOME}/go/src/github.com/luxfi/node/build
cd ${HOME}/go/src/github.com/luxfi/node
CC=x86_64-linux-musl-gcc \
CXX=x86_64-linux-musl-g++ \
CGO_ENABLED=1 \
STATIC_COMPILATION=1 \
GOOS=linux GOARCH=amd64 ./scripts/build.sh

find ${HOME}/go/src/github.com/luxfi/node/build
ls -lah ${HOME}/go/src/github.com/luxfi/node/build/plugins
```

You also need the `avalanched` daemon to run in the remote machines, which
can be downloaded from the release page
https://github.com/ava-labs/avalanche-ops/releases.

```bash
# this does not work... manually download for now...
curl -L \
https://github.com/ava-labs/avalanche-ops/releases/download/latest/avalanched-aws.x86_64-unknown-linux-gnu \
-o ${HOME}/avalanched-aws.x86_64-unknown-linux-gnu
```

## Step 3: Write avalanche-ops spec file

Now you need to write specification of how networks/nodes are to be
provisioned. Use `avalancheup-aws default-spec` to auto-generate the file
with some defaults.

```bash
avalancheup-aws default-spec \
--region us-west-2 \
--upload-artifacts-avalanched-aws-local-bin ./avalanched-aws.x86_64-unknown-linux-gnu \
--upload-artifacts-avalanchego-local-bin [LUXD_BUILD_DIR]/luxd \
--upload-artifacts-plugin-local-dir [LUXD_BUILD_DIR]/plugins \
--network-name custom \
--avalanchego-log-level INFO \
--spec-file-path spec.yaml
```

## Step 4: Apply the spec

Apply the spec to create resources:

```bash
# make sure you have access to your AWS account
ROLE_ARN=$(aws sts get-caller-identity --query Arn --output text);
echo $ROLE_ARN

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text);
echo ${ACCOUNT_ID}
```

```bash
avalancheup-aws apply --spec-file-path spec.yaml
avalancheup-aws delete --spec-file-path spec.yaml
```

Once `apply` command succeeds, the terminal outputs some helper commands
to access the instances:

```bash
chmod 400 test.key
# instance 'i-abc' (running, us-west-2a)
ssh -o "StrictHostKeyChecking no" -i test.key ubuntu@52.41.144.41
aws ssm start-session --region us-west-2 --target i-abc

# in the machine, you can run something like this
sudo tail -f /var/log/avalanched-aws.log
sudo tail -f /var/log/lux/luxd.log
ls -lah /data/

# logs are available in CloudWatch
# metrics are available in CloudWatch
```

## Step 5: Connect to MetaMask

```bash
# add custom network to MetaMask using the following chain ID and RPC
cat [YOUR_SPEC_PATH] | grep metamask_rpc:
cat [YOUR_SPEC_PATH] | grep chainId:

# use pre-funded test keys
cat [YOUR_SPEC_PATH] | grep private_key_hex:
```

## Step 6: Delete

Make sure to delete the resources if you don't need them anymore:

```bash
avalancheup-aws delete --spec-file-path spec.yaml

# add these if you don't need log groups
# --delete-cloudwatch-log-group \
# --delete-s3-objects
```

## Recipes

- If `avalancheup-aws default-spec --spec-file-path` is **non-empty**, test ID is set based on the file name.
- If `avalancheup-aws default-spec --spec-file-path` is **not specified (empty)**, test ID is auto-generated.

### Updates

```bash
curl -L \
https://github.com/ava-labs/avalanche-ops/releases/download/latest/avalanched-aws.x86_64-unknown-linux-gnu \
-o /tmp/avalanched-aws.x86_64-unknown-linux-gnu

chmod +x /tmp/avalanched-aws.x86_64-unknown-linux-gnu
/tmp/avalanched-aws.x86_64-unknown-linux-gnu --version





# update "avalanched"
# it runs "sudo systemctl stop luxd.service" and "restart"
sudo systemctl stop avalanched.service
sudo systemctl disable avalanched.service

sudo mv /tmp/avalanched-aws.x86_64-unknown-linux-gnu /usr/local/bin/avalanched-aws
/usr/local/bin/avalanched-aws --version

sudo systemctl enable avalanched.service
sudo systemctl restart --no-block avalanched.service

sudo tail /var/log/avalanched-aws.log
sudo tail -f /var/log/avalanched-aws.log
```

```bash
curl -L \
https://github.com/ava-labs/avalanche-telemetry/releases/download/latest/avalanche-telemetry-cloudwatch.x86_64-unknown-linux-gnu \
-o /tmp/lux-telemetry-cloudwatch-aws.x86_64-unknown-linux-gnu

chmod +x /tmp/lux-telemetry-cloudwatch-aws.x86_64-unknown-linux-gnu
/tmp/lux-telemetry-cloudwatch-aws.x86_64-unknown-linux-gnu --version





# update "lux-telemetry-cloudwatch"
sudo systemctl stop lux-telemetry-cloudwatch.service
sudo systemctl disable lux-telemetry-cloudwatch.service

sudo mv /tmp/lux-telemetry-cloudwatch-aws.x86_64-unknown-linux-gnu /usr/local/bin/lux-telemetry-cloudwatch
/usr/local/bin/lux-telemetry-cloudwatch --version

sudo systemctl enable lux-telemetry-cloudwatch.service
sudo systemctl restart --no-block lux-telemetry-cloudwatch.service

sudo tail /var/log/lux-telemetry-cloudwatch.log
sudo tail -f /var/log/lux-telemetry-cloudwatch.log
```

```bash
# update "LUX_TELEMETRY_CLOUDWATCH_RULES_FILE_PATH" for rules
vi /data/lux-telemetry-cloudwatch.rules.yaml
```

```bash
# https://github.com/luxfi/node/releases
VERSION=1.23.23
DOWNLOAD_URL=https://github.com/luxfi/node/releases/download/
rm -rf /tmp/luxd.tar.gz /tmp/luxd-v${VERSION}
curl -L ${DOWNLOAD_URL}/v${VERSION}/luxd-linux-amd64-v${VERSION}.tar.gz -o /tmp/luxd.tar.gz
tar xzvf /tmp/luxd.tar.gz -C /tmp
find /tmp/luxd-v${VERSION}

chmod +x /tmp/luxd-v${VERSION}/luxd
/tmp/luxd-v${VERSION}/luxd --version





# update "luxd"
sudo systemctl stop luxd.service
sudo systemctl disable luxd.service

sudo mv /tmp/luxd-v${VERSION}/luxd /usr/local/bin/luxd
/usr/local/bin/luxd --version

sudo systemctl enable luxd.service
sudo systemctl restart --no-block luxd.service

sudo tail /var/log/lux/luxd.log
sudo tail -f /var/log/lux/luxd.log
```

### Cheapest way to set up a network or validator

```bash
cd ${HOME}/avalanche-ops
./scripts/build.release.sh
```

```bash
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--network-name custom \
--instance-mode spot \
--volume-size-in-gb 300 \
--avalanchego-log-level INFO
```

```bash
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--network-name testnet \
--instance-mode spot \
--volume-size-in-gb 400 \
--avalanchego-log-level INFO
```

```bash
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--network-name mainnet \
--instance-mode spot \
--volume-size-in-gb 500 \
--avalanchego-log-level INFO
```

### Use static IP

Set `--ip-mode=elastic` to provision elastic IPs to be 1:1 mapped to a node ID via [`aws-ip-provisioners`](https://github.com/ava-labs/ip-manager):

```bash
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--network-name custom \
--instance-mode spot \
--ip-mode=elastic \
--volume-size-in-gb 300 \
--avalanchego-log-level INFO
```

### Custom network with NO initial database state

```bash
rm -rf ${HOME}/go/src/github.com/luxfi/node/build
cd ${HOME}/go/src/github.com/luxfi/node
CC=x86_64-linux-musl-gcc \
CXX=x86_64-linux-musl-g++ \
CGO_ENABLED=1 \
STATIC_COMPILATION=1 \
GOOS=linux GOARCH=amd64 ./scripts/build.sh
```

```bash
# to set the test ID "my-test-cluster"
# use "--spec-file-path ~/my-test-cluster.yaml"

##
# if compiled locally
AVALANCHED_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanched-aws
# download from https://github.com/ava-labs/avalanche-ops/releases
curl -L \
https://github.com/ava-labs/avalanche-ops/releases/download/latest/avalanched-aws.x86_64-unknown-linux-gnu \
-o ${HOME}/avalanched-aws.x86_64-unknown-linux-gnu
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHED_BIN_PATH=${HOME}/avalanched-aws.x86_64-unknown-linux-gnu

##
# if compiled locally
LUXD_BIN_PATH=${HOME}/go/src/github.com/luxfi/node/build/luxd
# if downloaded from https://github.com/luxfi/node/releases
VERSION=1.23.23
LUXD_BIN_PATH=/tmp/luxd-v${VERSION}/luxd

##
# if compiled locally
LUXD_PLUGINS_DIR_PATH=${HOME}/go/src/github.com/luxfi/node/build/plugins
# https://github.com/luxfi/node/releases
VERSION=1.23.23
DOWNLOAD_URL=https://github.com/luxfi/node/releases/download/
rm -rf /tmp/luxd.tar.gz /tmp/luxd-v${VERSION}
curl -L ${DOWNLOAD_URL}/v${VERSION}/luxd-linux-amd64-v${VERSION}.tar.gz -o /tmp/luxd.tar.gz
tar xzvf /tmp/luxd.tar.gz -C /tmp
find /tmp/luxd-v${VERSION}
# if downloaded from https://github.com/luxfi/node/releases
VERSION=1.23.23
LUXD_PLUGINS_DIR_PATH=/tmp/luxd-v${VERSION}/plugins

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--upload-artifacts-avalanched-aws-local-bin ${AVALANCHED_BIN_PATH} \
--upload-artifacts-avalanchego-local-bin ${LUXD_BIN_PATH} \
--upload-artifacts-plugin-local-dir ${LUXD_PLUGINS_DIR_PATH} \
--network-name custom \
--avalanchego-log-level DEBUG









# to run with the latest binaries automatically downloaded
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--network-name custom \
--avalanchego-log-level DEBUG

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--network-name custom \
--instance-mode spot \
--avalanchego-log-level DEBUG

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--network-name custom \
--instance-mode spot \
--avalanchego-log-level DEBUG








# to set your own AAD tag
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--aad-tag my-tag \
--network-name custom \
--avalanchego-log-level DEBUG

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws apply --spec-file-path [YOUR_SPEC_PATH]
```

### Custom network with NO initial database state, with EVM config file

See https://pkg.go.dev/github.com/luxfi/evm/plugin/evm#Config for more.

```bash
# or cross-compile on your machine using docker
# ./scripts/build.x86_64-linux-musl.sh

##
# if compiled locally
AVALANCHED_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanched-aws
# download from https://github.com/ava-labs/avalanche-ops/releases
curl -L \
https://github.com/ava-labs/avalanche-ops/releases/download/latest/avalanched-aws.x86_64-unknown-linux-gnu \
-o ${HOME}/avalanched-aws.x86_64-unknown-linux-gnu
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHED_BIN_PATH=${HOME}/avalanched-aws.x86_64-unknown-linux-gnu

##
# if compiled locally
LUXD_BIN_PATH=${HOME}/go/src/github.com/luxfi/node/build/luxd
# if downloaded from https://github.com/luxfi/node/releases
VERSION=1.23.23
LUXD_BIN_PATH=/tmp/luxd-v${VERSION}/luxd

##
# if compiled locally
LUXD_PLUGINS_DIR_PATH=${HOME}/go/src/github.com/luxfi/node/build/plugins
# https://github.com/luxfi/node/releases
VERSION=1.23.23
DOWNLOAD_URL=https://github.com/luxfi/node/releases/download/
rm -rf /tmp/luxd.tar.gz /tmp/luxd-v${VERSION}
curl -L ${DOWNLOAD_URL}/v${VERSION}/luxd-linux-amd64-v${VERSION}.tar.gz -o /tmp/luxd.tar.gz
tar xzvf /tmp/luxd.tar.gz -C /tmp
find /tmp/luxd-v${VERSION}
# if downloaded from https://github.com/luxfi/node/releases
VERSION=1.23.23
LUXD_PLUGINS_DIR_PATH=/tmp/luxd-v${VERSION}/plugins

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--upload-artifacts-avalanched-aws-local-bin ${AVALANCHED_BIN_PATH} \
--upload-artifacts-avalanchego-local-bin ${LUXD_BIN_PATH} \
--upload-artifacts-plugin-local-dir ${LUXD_PLUGINS_DIR_PATH} \
--coreth-metrics-enabled \
--coreth-continuous-profiler-enabled \
--coreth-offline-pruning-enabled \
--network-name custom \
--avalanchego-log-level INFO

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws apply --spec-file-path [YOUR_SPEC_PATH]
```

### Custom network with NO initial database state, with new install artifacts (trigger updates)

```bash
##
# if compiled locally
AVALANCHED_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanched-aws
# download from https://github.com/ava-labs/avalanche-ops/releases
curl -L \
https://github.com/ava-labs/avalanche-ops/releases/download/latest/avalanched-aws.x86_64-unknown-linux-gnu \
-o ${HOME}/avalanched-aws.x86_64-unknown-linux-gnu
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHED_BIN_PATH=${HOME}/avalanched-aws.x86_64-unknown-linux-gnu

##
# if compiled locally
LUXD_BIN_PATH=${HOME}/go/src/github.com/luxfi/node/build/luxd
# if downloaded from https://github.com/luxfi/node/releases
VERSION=1.23.23
LUXD_BIN_PATH=/tmp/luxd-v${VERSION}/luxd

##
# if compiled locally
LUXD_PLUGINS_DIR_PATH=${HOME}/go/src/github.com/luxfi/node/build/plugins
# https://github.com/luxfi/node/releases
VERSION=1.23.23
DOWNLOAD_URL=https://github.com/luxfi/node/releases/download/
rm -rf /tmp/luxd.tar.gz /tmp/luxd-v${VERSION}
curl -L ${DOWNLOAD_URL}/v${VERSION}/luxd-linux-amd64-v${VERSION}.tar.gz -o /tmp/luxd.tar.gz
tar xzvf /tmp/luxd.tar.gz -C /tmp
find /tmp/luxd-v${VERSION}
# if downloaded from https://github.com/luxfi/node/releases
VERSION=1.23.23
LUXD_PLUGINS_DIR_PATH=/tmp/luxd-v${VERSION}/plugins

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--upload-artifacts-avalanched-aws-local-bin ${AVALANCHED_BIN_PATH} \
--upload-artifacts-avalanchego-local-bin ${LUXD_BIN_PATH} \
--upload-artifacts-plugin-local-dir ${LUXD_PLUGINS_DIR_PATH} \
--network-name custom \
--avalanchego-log-level INFO

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws apply --spec-file-path [YOUR_SPEC_PATH]
```

```bash
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws events update-artifacts \
--upload-artifacts-avalanchego-local-bin ${LUXD_BIN_PATH} \
--upload-artifacts-plugin-local-dir ${LUXD_PLUGINS_DIR_PATH} \
--spec-file-path [YOUR_SPEC_PATH]
```

### Custom network with NO initial database state, with HTTP TLS enabled only for NLB DNS

TODOs
- Set up ACM CNAME with your DNS service (for subdomains).
- Set up CNAME record to point to the NLB DNS.

```bash
# REPLACE THIS WITH YOURS
ACM_CERT_ARN=arn:aws:acm:...:...:certificate/...

##
# if compiled locally
AVALANCHED_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanched-aws
# download from https://github.com/ava-labs/avalanche-ops/releases
curl -L \
https://github.com/ava-labs/avalanche-ops/releases/download/latest/avalanched-aws.x86_64-unknown-linux-gnu \
-o ${HOME}/avalanched-aws.x86_64-unknown-linux-gnu
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHED_BIN_PATH=${HOME}/avalanched-aws.x86_64-unknown-linux-gnu

##
# if compiled locally
LUXD_BIN_PATH=${HOME}/go/src/github.com/luxfi/node/build/luxd
# if downloaded from https://github.com/luxfi/node/releases
VERSION=1.23.23
LUXD_BIN_PATH=/tmp/luxd-v${VERSION}/luxd

##
# if compiled locally
LUXD_PLUGINS_DIR_PATH=${HOME}/go/src/github.com/luxfi/node/build/plugins
# https://github.com/luxfi/node/releases
VERSION=1.23.23
DOWNLOAD_URL=https://github.com/luxfi/node/releases/download/
rm -rf /tmp/luxd.tar.gz /tmp/luxd-v${VERSION}
curl -L ${DOWNLOAD_URL}/v${VERSION}/luxd-linux-amd64-v${VERSION}.tar.gz -o /tmp/luxd.tar.gz
tar xzvf /tmp/luxd.tar.gz -C /tmp
find /tmp/luxd-v${VERSION}
# if downloaded from https://github.com/luxfi/node/releases
VERSION=1.23.23
LUXD_PLUGINS_DIR_PATH=/tmp/luxd-v${VERSION}/plugins

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--upload-artifacts-avalanched-aws-local-bin ${AVALANCHED_BIN_PATH} \
--upload-artifacts-avalanchego-local-bin ${LUXD_BIN_PATH} \
--upload-artifacts-plugin-local-dir ${LUXD_PLUGINS_DIR_PATH} \
--nlb-acm-certificate-arns '{"us-west-2": "$ACM_CERT_ARN"}\
--network-name custom \
--avalanchego-log-level INFO

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws apply --spec-file-path [YOUR_SPEC_PATH]
```

```bash
cat ${HOME}/test-custom-https-for-nlb.yaml \
| grep cloudformation_asg_nlb_dns_name
# Use "https://[NLB_DNS]:443" for web wallet
```

### Custom network with NO initial database state, with HTTP TLS enabled only for `luxd`

```bash
##
# if compiled locally
AVALANCHED_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanched-aws
# download from https://github.com/ava-labs/avalanche-ops/releases
curl -L \
https://github.com/ava-labs/avalanche-ops/releases/download/latest/avalanched-aws.x86_64-unknown-linux-gnu \
-o ${HOME}/avalanched-aws.x86_64-unknown-linux-gnu
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHED_BIN_PATH=${HOME}/avalanched-aws.x86_64-unknown-linux-gnu

##
# if compiled locally
LUXD_BIN_PATH=${HOME}/go/src/github.com/luxfi/node/build/luxd
# if downloaded from https://github.com/luxfi/node/releases
VERSION=1.23.23
LUXD_BIN_PATH=/tmp/luxd-v${VERSION}/luxd

##
# if compiled locally
LUXD_PLUGINS_DIR_PATH=${HOME}/go/src/github.com/luxfi/node/build/plugins
# https://github.com/luxfi/node/releases
VERSION=1.23.23
DOWNLOAD_URL=https://github.com/luxfi/node/releases/download/
rm -rf /tmp/luxd.tar.gz /tmp/luxd-v${VERSION}
curl -L ${DOWNLOAD_URL}/v${VERSION}/luxd-linux-amd64-v${VERSION}.tar.gz -o /tmp/luxd.tar.gz
tar xzvf /tmp/luxd.tar.gz -C /tmp
find /tmp/luxd-v${VERSION}
# if downloaded from https://github.com/luxfi/node/releases
VERSION=1.23.23
LUXD_PLUGINS_DIR_PATH=/tmp/luxd-v${VERSION}/plugins

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--upload-artifacts-avalanched-aws-local-bin ${AVALANCHED_BIN_PATH} \
--upload-artifacts-avalanchego-local-bin ${LUXD_BIN_PATH} \
--upload-artifacts-plugin-local-dir ${LUXD_PLUGINS_DIR_PATH} \
--network-name custom \
--avalanchego-log-level INFO \
--avalanchego-http-tls-enabled \
--spec-file-path [YOUR_SPEC_PATH]

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws apply --spec-file-path [YOUR_SPEC_PATH]
```

### Custom network with NO initial database state, with quasar-machine

See https://pkg.go.dev/github.com/luxfi/node/snow for more (Quasar consensus).

```bash
##
# if compiled locally
AVALANCHED_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanched-aws
# download from https://github.com/ava-labs/avalanche-ops/releases
curl -L \
https://github.com/ava-labs/avalanche-ops/releases/download/latest/avalanched-aws.x86_64-unknown-linux-gnu \
-o ${HOME}/avalanched-aws.x86_64-unknown-linux-gnu
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHED_BIN_PATH=${HOME}/avalanched-aws.x86_64-unknown-linux-gnu

##
# if compiled locally
LUXD_BIN_PATH=${HOME}/go/src/github.com/luxfi/node/build/luxd
# if downloaded from https://github.com/luxfi/node/releases
VERSION=1.23.23
LUXD_BIN_PATH=/tmp/luxd-v${VERSION}/luxd

##
# if compiled locally
LUXD_PLUGINS_DIR_PATH=${HOME}/go/src/github.com/luxfi/node/build/plugins
# https://github.com/luxfi/node/releases
VERSION=1.23.23
DOWNLOAD_URL=https://github.com/luxfi/node/releases/download/
rm -rf /tmp/luxd.tar.gz /tmp/luxd-v${VERSION}
curl -L ${DOWNLOAD_URL}/v${VERSION}/luxd-linux-amd64-v${VERSION}.tar.gz -o /tmp/luxd.tar.gz
tar xzvf /tmp/luxd.tar.gz -C /tmp
find /tmp/luxd-v${VERSION}
# if downloaded from https://github.com/luxfi/node/releases
VERSION=1.23.23
LUXD_PLUGINS_DIR_PATH=/tmp/luxd-v${VERSION}/plugins

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--upload-artifacts-avalanched-aws-local-bin ${AVALANCHED_BIN_PATH} \
--upload-artifacts-avalanchego-local-bin ${LUXD_BIN_PATH} \
--upload-artifacts-plugin-local-dir ${LUXD_PLUGINS_DIR_PATH} \
--upload-artifacts-snow-machine-file-path ${HOME}/evm.json \
--network-name custom \
---keys-to-generate 5 \
--avalanchego-log-level INFO

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws apply --spec-file-path [YOUR_SPEC_PATH]
```

### Custom network with initial database state

TODO: network forking

### Custom network with NO initial database state, with evm

First, make sure you have `evm` installed in your local machine (for uploads).

Install the following:
- https://github.com/luxfi/evm
- https://github.com/luxfi/cli

See ["install `evm` in the custom network"](./example-aws.md#optional-install-evm-in-the-custom-network) for demo.

```bash
rm -rf ${HOME}/go/src/github.com/luxfi/node/build
cd ${HOME}/go/src/github.com/luxfi/node
CC=x86_64-linux-musl-gcc \
CXX=x86_64-linux-musl-g++ \
CGO_ENABLED=1 \
STATIC_COMPILATION=1 \
GOOS=linux GOARCH=amd64 ./scripts/build.sh

cd ${HOME}/go/src/github.com/luxfi/evm
CC=x86_64-linux-musl-gcc \
CXX=x86_64-linux-musl-g++ \
CGO_ENABLED=1 \
STATIC_COMPILATION=1 \
GOOS=linux GOARCH=amd64 ./scripts/build.sh \
${HOME}/go/src/github.com/luxfi/node/build/plugins/mgj786NP7uDwBCcq6YwThhaN8FLyybkCa4zBWTQbNgmK6k9A6
```

```bash
cd ${HOME}/go/src/github.com/luxfi/cli
go install -v .
lux subnet create VMID subnetevm
# mgj786NP7uDwBCcq6YwThhaN8FLyybkCa4zBWTQbNgmK6k9A6
```

```bash
##
# if compiled locally
AVALANCHED_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanched-aws
# download from https://github.com/ava-labs/avalanche-ops/releases
curl -L \
https://github.com/ava-labs/avalanche-ops/releases/download/latest/avalanched-aws.x86_64-unknown-linux-gnu \
-o ${HOME}/avalanched-aws.x86_64-unknown-linux-gnu
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHED_BIN_PATH=${HOME}/avalanched-aws.x86_64-unknown-linux-gnu

##
# if compiled locally
LUXD_BIN_PATH=${HOME}/go/src/github.com/luxfi/node/build/luxd
# if downloaded from https://github.com/luxfi/node/releases
VERSION=1.23.23
LUXD_BIN_PATH=/tmp/luxd-v${VERSION}/luxd

##
# if compiled locally
LUXD_PLUGINS_DIR_PATH=${HOME}/go/src/github.com/luxfi/node/build/plugins
# https://github.com/luxfi/node/releases
VERSION=1.23.23
DOWNLOAD_URL=https://github.com/luxfi/node/releases/download/
rm -rf /tmp/luxd.tar.gz /tmp/luxd-v${VERSION}
curl -L ${DOWNLOAD_URL}/v${VERSION}/luxd-linux-amd64-v${VERSION}.tar.gz -o /tmp/luxd.tar.gz
tar xzvf /tmp/luxd.tar.gz -C /tmp
find /tmp/luxd-v${VERSION}
# if downloaded from https://github.com/luxfi/node/releases
VERSION=1.23.23
LUXD_PLUGINS_DIR_PATH=/tmp/luxd-v${VERSION}/plugins





#####
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--upload-artifacts-avalanched-aws-local-bin ${AVALANCHED_BIN_PATH} \
--upload-artifacts-avalanchego-local-bin ${LUXD_BIN_PATH} \
--upload-artifacts-plugin-local-dir ${LUXD_PLUGINS_DIR_PATH} \
--network-name custom \
--avalanchego-log-level INFO \
--evms 1

#####
LUXD_BIN_PATH=${HOME}/go/src/github.com/luxfi/node/build/luxd
LUXD_PLUGINS_DIR_PATH=${HOME}/go/src/github.com/luxfi/node/build/plugins
rm -rf ${HOME}/evm-test-keys
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--upload-artifacts-avalanchego-local-bin ${LUXD_BIN_PATH} \
--upload-artifacts-plugin-local-dir ${LUXD_PLUGINS_DIR_PATH} \
--instance-mode spot \
--network-name custom \
--avalanchego-log-level INFO \
--keys-to-generate 30 \
--key-files-dir ${HOME}/evm-test-keys \
--evms 1

#####
LUXD_BIN_PATH=${HOME}/go/src/github.com/luxfi/node/build/luxd
LUXD_PLUGINS_DIR_PATH=${HOME}/go/src/github.com/luxfi/node/build/plugins
rm -rf ${HOME}/evm-test-keys
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--upload-artifacts-avalanchego-local-bin ${LUXD_BIN_PATH} \
--upload-artifacts-plugin-local-dir ${LUXD_PLUGINS_DIR_PATH} \
--instance-mode spot \
--network-name custom \
--avalanchego-log-level INFO \
--keys-to-generate 30 \
--key-files-dir ${HOME}/evm-test-keys \
--evms 1

# e.g., adjust gas limit
# https://www.rapidtables.com/convert/number/hex-to-decimal.html
# 1000000
# 0xF4240

# this will print out the list of commands to create resources
```

```bash
# only if you want to delete s3 objects + cloudwatch logs + EIPs
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws delete \
--delete-cloudwatch-log-group \
--delete-s3-objects \
--delete-ebs-volumes \
--delete-elastic-ips \
--spec-file-path [YOUR_SPEC_PATH]
```

Once the custom network is created, run the following commands to get the test key, RPC endpoints, and node IDs:

```bash
# make sure to pick the second "private_key_hex" or later keys
# that has immediately unlocked P-chain balance
cat [YOUR_SPEC_PATH] | grep private_key_hex:

  private_key_hex: ...
    private_key_hex: mykeyinhex
    ...

cat <<EOF > /tmp/test.key
...
EOF
cat /tmp/test.key
```

```bash
# to get HTTP RPC endpoints
cat [YOUR_SPEC_PATH] | grep http_rpc:
```

`apply` command will output the following. Use the following to get access to each EC2 instance:

```bash
chmod 400 /Users/gyuho.lee/aops-custom-202203-2wh8w4-ec2-access.key
# ...
```

```bash
# when "55Wgss7ie3Xo42pmt85Y2FwbHo4tgwpgxSeyLAhtD4ivXjto1" is the blockchain ID
# for instance, the lux cli will return
# created blockchain "55Wgss7ie3Xo42pmt85Y2FwbHo4tgwpgxSeyLAhtD4ivXjto1" (took 179.72724ms)
cat [YOUR_SPEC_PATH] | grep metamask_rpc:

# use the blockchain ID for metamask RPC
# or use the public IP of the validator node
http://[PUBLIC-DNS]:9650/ext/bc/55Wgss7ie3Xo42pmt85Y2FwbHo4tgwpgxSeyLAhtD4ivXjto1/rpc

# check the logs
sudo tail /var/log/lux/55Wgss7ie3Xo42pmt85Y2FwbHo4tgwpgxSeyLAhtD4ivXjto1.log
```

### Testnet network with NO initial database state

This will sync from peer (rather than downloading from S3):

```bash
##
# if compiled locally
AVALANCHED_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanched-aws
# download from https://github.com/ava-labs/avalanche-ops/releases
curl -L \
https://github.com/ava-labs/avalanche-ops/releases/download/latest/avalanched-aws.x86_64-unknown-linux-gnu \
-o ${HOME}/avalanched-aws.x86_64-unknown-linux-gnu
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHED_BIN_PATH=${HOME}/avalanched-aws.x86_64-unknown-linux-gnu

##
# if compiled locally
LUXD_BIN_PATH=${HOME}/go/src/github.com/luxfi/node/build/luxd
# if downloaded from https://github.com/luxfi/node/releases
VERSION=1.23.23
LUXD_BIN_PATH=/tmp/luxd-v${VERSION}/luxd

##
# if compiled locally
LUXD_PLUGINS_DIR_PATH=${HOME}/go/src/github.com/luxfi/node/build/plugins
# https://github.com/luxfi/node/releases
VERSION=1.23.23
DOWNLOAD_URL=https://github.com/luxfi/node/releases/download/
rm -rf /tmp/luxd.tar.gz /tmp/luxd-v${VERSION}
curl -L ${DOWNLOAD_URL}/v${VERSION}/luxd-linux-amd64-v${VERSION}.tar.gz -o /tmp/luxd.tar.gz
tar xzvf /tmp/luxd.tar.gz -C /tmp
find /tmp/luxd-v${VERSION}
# if downloaded from https://github.com/luxfi/node/releases
VERSION=1.23.23
LUXD_PLUGINS_DIR_PATH=/tmp/luxd-v${VERSION}/plugins

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--upload-artifacts-avalanched-aws-local-bin ${AVALANCHED_BIN_PATH} \
--upload-artifacts-avalanchego-local-bin ${LUXD_BIN_PATH} \
--upload-artifacts-plugin-local-dir ${LUXD_PLUGINS_DIR_PATH} \
--network-name testnet \
--avalanchego-log-level INFO







# to download install artifacts on remote machines automatically
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--network-name testnet \
--avalanchego-log-level INFO

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--network-name testnet \
--instance-mode spot \
--avalanchego-log-level INFO







cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws apply --spec-file-path [YOUR_SPEC_PATH]
```

### Testnet network with NO initial database state, with "avalanched-aws" lite mode

This will sync from peer (rather than downloading from S3):

```bash
##
# if compiled locally
AVALANCHED_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanched-aws
# download from https://github.com/ava-labs/avalanche-ops/releases
curl -L \
https://github.com/ava-labs/avalanche-ops/releases/download/latest/avalanched-aws.x86_64-unknown-linux-gnu \
-o ${HOME}/avalanched-aws.x86_64-unknown-linux-gnu
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHED_BIN_PATH=${HOME}/avalanched-aws.x86_64-unknown-linux-gnu

# download latest binary from github
cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--avalanched-use-default-config \
--upload-artifacts-avalanched-aws-local-bin ${AVALANCHED_BIN_PATH} \
--network-name testnet \
--avalanchego-log-level INFO

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws apply --spec-file-path [YOUR_SPEC_PATH]
```

### Testnet network with NO initial database state, with fast-sync

This will fast-sync from peer (rather than downloading from S3):

```bash
##
# if compiled locally
AVALANCHED_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanched-aws
# download from https://github.com/ava-labs/avalanche-ops/releases
curl -L \
https://github.com/ava-labs/avalanche-ops/releases/download/latest/avalanched-aws.x86_64-unknown-linux-gnu \
-o ${HOME}/avalanched-aws.x86_64-unknown-linux-gnu
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHED_BIN_PATH=${HOME}/avalanched-aws.x86_64-unknown-linux-gnu

##
# if compiled locally
LUXD_BIN_PATH=${HOME}/go/src/github.com/luxfi/node/build/luxd
# if downloaded from https://github.com/luxfi/node/releases
VERSION=1.23.23
LUXD_BIN_PATH=/tmp/luxd-v${VERSION}/luxd

##
# if compiled locally
LUXD_PLUGINS_DIR_PATH=${HOME}/go/src/github.com/luxfi/node/build/plugins
# https://github.com/luxfi/node/releases
VERSION=1.23.23
DOWNLOAD_URL=https://github.com/luxfi/node/releases/download/
rm -rf /tmp/luxd.tar.gz /tmp/luxd-v${VERSION}
curl -L ${DOWNLOAD_URL}/v${VERSION}/luxd-linux-amd64-v${VERSION}.tar.gz -o /tmp/luxd.tar.gz
tar xzvf /tmp/luxd.tar.gz -C /tmp
find /tmp/luxd-v${VERSION}
# if downloaded from https://github.com/luxfi/node/releases
VERSION=1.23.23
LUXD_PLUGINS_DIR_PATH=/tmp/luxd-v${VERSION}/plugins

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--upload-artifacts-avalanched-aws-local-bin ${AVALANCHED_BIN_PATH} \
--upload-artifacts-avalanchego-local-bin ${LUXD_BIN_PATH} \
--upload-artifacts-plugin-local-dir ${LUXD_PLUGINS_DIR_PATH} \
--network-name testnet \
--avalanchego-log-level INFO \
--avalanchego-state-sync-ids ... \
--avalanchego-state-sync-ips ... \
--spec-file-path [YOUR_SPEC_PATH]

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws apply --spec-file-path [YOUR_SPEC_PATH]
```

### Main network with NO initial database state

This will sync from peer (rather than downloading from S3):

```bash
##
# if compiled locally
AVALANCHED_BIN_PATH=./target/x86_64-unknown-linux-musl/release/avalanched-aws
# download from https://github.com/ava-labs/avalanche-ops/releases
curl -L \
https://github.com/ava-labs/avalanche-ops/releases/download/latest/avalanched-aws.x86_64-unknown-linux-gnu \
-o ${HOME}/avalanched-aws.x86_64-unknown-linux-gnu
# if downloaded from https://github.com/ava-labs/avalanche-ops/releases
AVALANCHED_BIN_PATH=${HOME}/avalanched-aws.x86_64-unknown-linux-gnu

##
# if compiled locally
LUXD_BIN_PATH=${HOME}/go/src/github.com/luxfi/node/build/luxd
# if downloaded from https://github.com/luxfi/node/releases
VERSION=1.23.23
LUXD_BIN_PATH=/tmp/luxd-v${VERSION}/luxd

##
# if compiled locally
LUXD_PLUGINS_DIR_PATH=${HOME}/go/src/github.com/luxfi/node/build/plugins
# https://github.com/luxfi/node/releases
VERSION=1.23.23
DOWNLOAD_URL=https://github.com/luxfi/node/releases/download/
rm -rf /tmp/luxd.tar.gz /tmp/luxd-v${VERSION}
curl -L ${DOWNLOAD_URL}/v${VERSION}/luxd-linux-amd64-v${VERSION}.tar.gz -o /tmp/luxd.tar.gz
tar xzvf /tmp/luxd.tar.gz -C /tmp
find /tmp/luxd-v${VERSION}
# if downloaded from https://github.com/luxfi/node/releases
VERSION=1.23.23
LUXD_PLUGINS_DIR_PATH=/tmp/luxd-v${VERSION}/plugins

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--upload-artifacts-avalanched-aws-local-bin ${AVALANCHED_BIN_PATH} \
--upload-artifacts-avalanchego-local-bin ${LUXD_BIN_PATH} \
--upload-artifacts-plugin-local-dir ${LUXD_PLUGINS_DIR_PATH} \
--network-name mainnet \
--avalanchego-log-level INFO


cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--network-name mainnet \
--instance-mode spot \
--avalanchego-log-level INFO

cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws default-spec \
--region us-west-2 \
--network-name mainnet \
--instance-mode spot \
--avalanchego-log-level INFO


cd ${HOME}/avalanche-ops
./target/release/avalancheup-aws apply --spec-file-path [YOUR_SPEC_PATH]
```

## FAQ: What if I want to control the systemd service manually?

`avalancheup` can help you set up infrastructure, but you may want full control over Lux nodes for some tweaks. You can disable all systemd services for `avalancheup` as follows:

```bash
sudo systemctl cat avalanched.service
sudo systemctl status avalanched.service
sudo systemctl stop avalanched.service
sudo systemctl disable avalanched.service
sudo journalctl -f -u avalanched.service
sudo journalctl -u avalanched.service --lines=10 --no-pager
sudo tail -f /var/log/avalanched-aws.log

sudo systemctl cat luxd.service
sudo systemctl status luxd.service
sudo systemctl stop luxd.service
sudo systemctl disable luxd.service
sudo journalctl -f -u luxd.service
sudo journalctl -u luxd.service --lines=10 --no-pager
sudo tail -f /var/log/lux/luxd.log
```
