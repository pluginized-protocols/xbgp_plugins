#! /bin/bash -e

info () {
    echo -e "[INFO] ${*}"
}

PLUGINS=($(ls -d */ | sed -E "s/\///g;s/xbgp_compliant_api//g;s/docs//g;s/prove_stuffs//g"))
for PLUGIN in ${PLUGINS[@]}
do
    tar cjf "${PLUGIN}.tar.bz2" -h "${PLUGIN}" xbgp_compliant_api/*.h prove_stuffs/{*.h,*.c} *.h
    info "${PLUGIN} archived."
done
