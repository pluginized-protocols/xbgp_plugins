#! /bin/bash -e

info() {
  echo -e "[INFO] ${*}"
}

list_dir() {
  find "$1" -type d ! -path '*docs*' ! \
    -path '*git*' ! -path '*venv*' ! \
    -path '*cmake*' ! -path '*idea*' ! \
    -path '*xbgp_compliant_api*' ! -path '*prove_stuffs*'
}

mapfile -t < <(list_dir . | sed -E "s/^\.$//g")
for PLUGIN in "${MAPFILE[@]}"; do
  if [ -n "$PLUGIN" ]; then
    tar cjf "${PLUGIN}.tar.bz2" -h "${PLUGIN}" xbgp_compliant_api/*.h prove_stuffs/{*.h,*.c} ./*.h
    info "${PLUGIN} archived."
  fi
done
