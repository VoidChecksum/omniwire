_omniwire() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local commands="--stdio --sse-port --rest-port --no-sync --version --help"
    COMPREPLY=($(compgen -W "$commands" -- "$cur"))
}
complete -F _omniwire omniwire
complete -F _omniwire ow
