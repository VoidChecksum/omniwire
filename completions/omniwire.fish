complete -c omniwire -l stdio -d 'MCP stdio transport'
complete -c omniwire -l sse-port -d 'SSE transport port' -x
complete -c omniwire -l rest-port -d 'REST transport port' -x
complete -c omniwire -l no-sync -d 'Disable CyberSync'
complete -c omniwire -l version -d 'Show version'
complete -c omniwire -l help -d 'Show help'
# Alias
complete -c ow -w omniwire
