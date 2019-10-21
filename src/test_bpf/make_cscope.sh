#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

TOP=${DIR}/../../

find ${TOP}/linux/tools/{lib/,}/bpf -name '*.[ch]' > ${DIR}/cscope.files
find ${TOP}/linux/samples/bpf -name '*.[ch]' >> ${DIR}/cscope.files
pushd ${DIR}
cscope -kb


