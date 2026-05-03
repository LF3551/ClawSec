# Bash completion for clawsec
_clawsec() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    opts="-l -p -k -K -L -u -4 -6 -c -v -w -e -z -P -V -n -h --obfs --pad --jitter --ech --mux --fallback --fingerprint --tofu --pq"

    case "${prev}" in
        -p|-w)
            # Port or timeout - expect number
            return 0
            ;;
        -k)
            # Password - no completion
            return 0
            ;;
        -e)
            # Program path
            COMPREPLY=( $(compgen -c -- "${cur}") )
            return 0
            ;;
        -L)
            # host:port - no completion
            return 0
            ;;
        --obfs)
            COMPREPLY=( $(compgen -W "http tls" -- "${cur}") )
            return 0
            ;;
        --jitter)
            # Milliseconds - expect number
            return 0
            ;;
        --fallback)
            # host:port - no completion
            return 0
            ;;
        --fingerprint)
            COMPREPLY=( $(compgen -W "chrome firefox safari" -- "$cur") )
            return 0
            ;;
    esac

    if [[ "${cur}" == -* ]]; then
        COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
        return 0
    fi

    # Default: hostname completion
    COMPREPLY=( $(compgen -A hostname -- "${cur}") )
}

complete -F _clawsec clawsec
