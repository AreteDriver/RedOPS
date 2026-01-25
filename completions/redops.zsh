#compdef redops

# Zsh completion for RedOPS
# Install: Add to fpath or source directly
# Example: fpath=(~/.zsh/completions $fpath)

_redops() {
    local -a commands
    local -a scan_presets
    local -a ai_actions
    local -a apikey_actions
    local -a config_actions
    local -a formats
    local -a providers

    commands=(
        'scan:Run security scan'
        'report:Generate report'
        'modules:List available modules'
        'presets:List scan presets'
        'config:Manage configuration'
        'settings:Open interactive settings menu'
        'apikey:Manage API keys'
        'ai:AI-assisted analysis'
        'version:Show version'
    )

    scan_presets=(
        'quick:Fast reconnaissance'
        'recon:Comprehensive reconnaissance'
        'full:Complete security assessment'
        'compliance:Compliance-focused assessment'
        'infrastructure:Cloud and infrastructure focused'
        'threat_intel:Threat indicator analysis'
        'executive:Executive report generation'
        'ai_enhanced:AI-powered full assessment'
    )

    ai_actions=(
        'analyze:Analyze scan findings'
        'explain:Explain security concepts'
        'suggest:Get remediation suggestions'
        'summarize:Generate executive summary'
        'chat:Interactive Q&A'
    )

    apikey_actions=(
        'list:List configured API keys'
        'set:Set an API key'
        'get:Get an API key'
        'remove:Remove an API key'
    )

    config_actions=(
        'show:Show current configuration'
        'init:Initialize configuration'
        'path:Show config file path'
    )

    formats=(
        'json:JSON format'
        'html:HTML format'
        'markdown:Markdown format'
        'text:Plain text format'
        'summary:Summary format'
    )

    providers=(
        'openai:OpenAI GPT models'
        'anthropic:Anthropic Claude models'
    )

    _arguments -C \
        '-h[Show help]' \
        '--help[Show help]' \
        '-v[Increase verbosity]' \
        '--verbose[Increase verbosity]' \
        '-q[Suppress output]' \
        '--quiet[Suppress output]' \
        '--no-color[Disable colored output]' \
        '-o[Output directory]:directory:_files -/' \
        '--output-dir[Output directory]:directory:_files -/' \
        '-f[Output format]:format:(json html markdown text summary)' \
        '--format[Output format]:format:(json html markdown text summary)' \
        '--config[Config file]:file:_files -g "*.json"' \
        '--dry-run[Dry run mode]' \
        '1:command:->command' \
        '*::arg:->args'

    case $state in
        command)
            _describe -t commands 'redops command' commands
            ;;
        args)
            case $words[1] in
                scan)
                    _arguments \
                        '--preset[Scan preset]:preset:((${(kv)scan_presets}))' \
                        '-p[Scan preset]:preset:((${(kv)scan_presets}))' \
                        '--modules[Modules to run]:modules:' \
                        '-m[Modules to run]:modules:' \
                        '*:target:'
                    ;;
                ai)
                    _arguments \
                        '1:action:->ai_action' \
                        '--input[Input file]:file:_files -g "*.json"' \
                        '-i[Input file]:file:_files -g "*.json"' \
                        '--query[Query text]:query:' \
                        '-q[Query text]:query:' \
                        '--context[Context file]:file:_files -g "*.json"' \
                        '-x[Context file]:file:_files -g "*.json"' \
                        '--provider[AI provider]:provider:((${(kv)providers}))' \
                        '-p[AI provider]:provider:((${(kv)providers}))' \
                        '--model[Model name]:model:'
                    case $state in
                        ai_action)
                            _describe -t ai_actions 'AI action' ai_actions
                            ;;
                    esac
                    ;;
                apikey)
                    _arguments \
                        '1:action:->apikey_action' \
                        '--provider[Provider]:provider:((${(kv)providers}))' \
                        '-p[Provider]:provider:((${(kv)providers}))'
                    case $state in
                        apikey_action)
                            _describe -t apikey_actions 'API key action' apikey_actions
                            ;;
                    esac
                    ;;
                config)
                    _describe -t config_actions 'Config action' config_actions
                    ;;
                report)
                    _arguments \
                        '--input[Input file]:file:_files -g "*.json"' \
                        '-i[Input file]:file:_files -g "*.json"' \
                        '--type[Report type]:type:(executive technical summary json)' \
                        '-t[Report type]:type:(executive technical summary json)' \
                        '--output[Output file]:file:_files'
                    ;;
            esac
            ;;
    esac
}

_redops "$@"
