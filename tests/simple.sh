#!/usr/bin/env bash
#
# TODO: Maybe this should use chutney, instead of the production network,
# although it probably does not really matter for a client.

set -euo pipefail

CMD="./oniux --onionmasq ~/onionmasq/target/debug/onionmasq"

$CMD curl -4 https://amiusingtor.net | grep "^yes "
$CMD curl -6 https://amiusingtor.net | grep "^yes "
