# Screen for linux

```bash

# Start a new screen session
screen

# Start a named screen session
screen -S session_name

# Detach from a screen session
# Press Ctrl + A, then d
# (Ctrl + A followed by d)
 
# List available screen sessions
screen -ls

# Reattach to a screen session
screen -r session_name

# Reattach to a detached screen session
screen -r

# Kill a screen session
screen -X -S session_name quit

# Create a new window in a screen session
# Press Ctrl + A, then c
# (Ctrl + A followed by c)

# Switch between windows
# Press Ctrl + A, then n (next) or p (previous)
# (Ctrl + A followed by n or p)

# Scroll in a window
# Press Ctrl + A, then [ to enter scroll mode
# Use arrow keys or Page Up/Down
# Press Esc to exit scroll mode
# (Ctrl + A followed by [)

# Split the screen vertically
# Press Ctrl + A, then | (pipe)
# (Ctrl + A followed by |)

# Split the screen horizontally
# Press Ctrl + A, then S (uppercase)
# (Ctrl + A followed by Shift + S)

# Switch between split panes
# Press Ctrl + A, then Tab
# (Ctrl + A followed by Tab)

# Close a split pane
# Press Ctrl + A, then X
# (Ctrl + A followed by Shift + X)

# Name a window
# Press Ctrl + A, then A, then type the name
# (Ctrl + A followed by A)

# Send a command to all windows in a session
# Press Ctrl + A, then : to enter command mode
# Type 'at "#" stuff "command"' where '#' is the window number
# (Ctrl + A followed by :)
 
# Get help
# Press Ctrl + A, then ?
# (Ctrl + A followed by ?)

```