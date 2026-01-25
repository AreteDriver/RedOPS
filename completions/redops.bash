# Bash completion for RedOPS
# Install: source /path/to/redops.bash
# Or copy to /etc/bash_completion.d/redops

_redops_completions() {
    local cur prev words cword
    _init_completion || return

    local commands="scan report modules presets config settings apikey ai version"
    local scan_presets="quick recon full compliance infrastructure threat_intel executive ai_enhanced"
    local ai_actions="analyze explain suggest summarize chat"
    local apikey_actions="list set get remove"
    local config_actions="show init path"
    local formats="json html markdown text summary"
    local providers="openai anthropic"

    case "${prev}" in
        redops)
            COMPREPLY=($(compgen -W "${commands}" -- "${cur}"))
            return 0
            ;;
        scan)
            # Complete with presets or files
            COMPREPLY=($(compgen -W "--preset --modules --output-dir --format --dry-run" -- "${cur}"))
            return 0
            ;;
        --preset|-p)
            COMPREPLY=($(compgen -W "${scan_presets}" -- "${cur}"))
            return 0
            ;;
        --format|-f)
            COMPREPLY=($(compgen -W "${formats}" -- "${cur}"))
            return 0
            ;;
        --provider)
            COMPREPLY=($(compgen -W "${providers}" -- "${cur}"))
            return 0
            ;;
        ai)
            COMPREPLY=($(compgen -W "${ai_actions}" -- "${cur}"))
            return 0
            ;;
        apikey)
            COMPREPLY=($(compgen -W "${apikey_actions}" -- "${cur}"))
            return 0
            ;;
        config)
            COMPREPLY=($(compgen -W "${config_actions}" -- "${cur}"))
            return 0
            ;;
        analyze|suggest|summarize)
            COMPREPLY=($(compgen -W "--input -i --context -x" -- "${cur}"))
            return 0
            ;;
        explain|chat)
            COMPREPLY=($(compgen -W "--query -q --context -x --provider -p --model -m" -- "${cur}"))
            return 0
            ;;
        --input|-i|--context|-x)
            # Complete with JSON files
            COMPREPLY=($(compgen -f -X '!*.json' -- "${cur}"))
            return 0
            ;;
        --output-dir|-o)
            # Complete with directories
            COMPREPLY=($(compgen -d -- "${cur}"))
            return 0
            ;;
    esac

    # Default to command completion
    if [[ ${cword} -eq 1 ]]; then
        COMPREPLY=($(compgen -W "${commands}" -- "${cur}"))
    fi
}

complete -F _redops_completions redops
