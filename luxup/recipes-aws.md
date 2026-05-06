# luxup AWS recipes (quick start)

These recipes wrap the upstream `avalancheup-aws` provisioner so it deploys
**`luxd`** (`github.com/luxfi/node`) instead of upstream `avalanchego`. The
provisioner CLI keeps its upstream name because Lux does not yet ship an
equivalent (`luxup-aws`) — flagged for follow-up migration.

To download the provisioner from release, visit
https://github.com/ava-labs/avalanche-ops/releases.

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

```bash
# 1. simple, default spot instance + elastic IP
# all plugins/binaries are downloaded automatic in the hosts
avalancheup-aws default-spec --network-name custom
```

```bash
# 2. simple, default spot instance + elastic IP, subnet-evm
# all plugins/binaries are downloaded automatic in the hosts
avalancheup-aws default-spec --network-name custom --subnet-evms 1
```

```bash
# 3. simple, subnet-evm with custom luxd binary
# some plugins/binaries are downloaded automatic from S3 to the hosts
avalancheup-aws default-spec \
--upload-artifacts-avalanchego-local-bin ${LUXD_BIN_PATH} \
--upload-artifacts-plugin-local-dir ${LUXD_PLUGIN_DIR_PATH} \
--instance-mode=on-demand \
--ip-mode=elastic \
--network-name custom \
--keys-to-generate 5 \
--subnet-evms 1
```

```bash
# 4. advanced, subnet-evm with custom luxd binary
# all plugins/binaries are downloaded automatic from S3 to the hosts
LUXDD_BIN_PATH=/home/ubuntu/avalanche-ops/target/release/avalanched-aws
AWS_VOLUME_PROVISIONER_BIN_PATH=/tmp/aws-volume-provisioner-new
AWS_IP_PROVISIONER_BIN_PATH=/tmp/aws-ip-provisioner-new
LUX_TELEMETRY_CLOUDWATCH_BIN_PATH=/tmp/lux-telemetry-cloudwatch
LUXD_BIN_PATH=/home/ubuntu/go/src/github.com/luxfi/node/build/luxd
LUXD_PLUGIN_DIR_PATH=/home/ubuntu/go/src/github.com/luxfi/node/build/plugins

cd /home/ubuntu/avalanche-ops
avalancheup-aws default-spec \
--region ap-northeast-2 \
--upload-artifacts-avalanched-aws-local-bin ${LUXDD_BIN_PATH} \
--upload-artifacts-aws-volume-provisioner-local-bin ${AWS_VOLUME_PROVISIONER_BIN_PATH} \
--upload-artifacts-aws-ip-provisioner-local-bin ${AWS_IP_PROVISIONER_BIN_PATH} \
--upload-artifacts-avalanche-telemetry-cloudwatch-local-bin ${LUX_TELEMETRY_CLOUDWATCH_BIN_PATH} \
--upload-artifacts-avalanchego-local-bin ${LUXD_BIN_PATH} \
--upload-artifacts-plugin-local-dir ${LUXD_PLUGIN_DIR_PATH} \
--instance-mode=on-demand \
--ip-mode=elastic \
--network-name custom \
--keys-to-generate 50 \
--keys-to-generate-type hot \
--subnet-evms 1
```

> Note: the upstream provisioner flags retain their `--upload-artifacts-avalanchego-local-bin`
> name. They accept the `luxd` binary unchanged because the on-disk layout matches.
