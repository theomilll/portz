# portwatch

`portwatch` installs a lightweight terminal UI named `portz`.

Run it to see code/dev TCP listener processes owned by your current macOS/Linux user:

```sh
portz
```

Controls:

- Up/Down: move selection
- `r`: refresh
- `K`: request kill for the selected process
- `K` again: send `SIGTERM` to that process
- `Esc`: cancel a pending kill confirmation
- `q` or Ctrl-C: quit

The scanner uses `lsof -a -u "$USER" -nP -iTCP -sTCP:LISTEN -F0pcLn` so port and process ownership comes from the operating system, with numeric ports and no DNS lookups. It then keeps likely code processes using command names, command-line markers, and process cwd.
