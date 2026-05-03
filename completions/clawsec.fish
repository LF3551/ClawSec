# Fish completion for clawsec
complete -c clawsec -s l -d 'Listen mode for inbound connections'
complete -c clawsec -s p -x -d 'Local port number'
complete -c clawsec -s k -x -d 'Encryption password (required)'
complete -c clawsec -s c -d 'Chat mode with timestamps and colors'
complete -c clawsec -s v -d 'Verbose output'
complete -c clawsec -s w -x -d 'Connection timeout in seconds'
complete -c clawsec -s e -r -F -d 'Execute program after connect'
complete -c clawsec -s h -d 'Display usage information'
