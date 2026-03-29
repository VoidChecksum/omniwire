#compdef omniwire ow
_omniwire() {
    _arguments \
        '--stdio[MCP stdio transport]' \
        '--sse-port=[SSE transport port]:port:' \
        '--rest-port=[REST transport port]:port:' \
        '--no-sync[Disable CyberSync]' \
        '--version[Show version]' \
        '--help[Show help]'
}
_omniwire "$@"
