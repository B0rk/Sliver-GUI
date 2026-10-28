# Sliver GUI — reference

The complete feature and usage reference. For a quick overview, installation and first
connection, see the [README](../README.md).

## Features

### Workspace & layout
- **Dockable panels** — drag, split and rearrange anything. The default layout puts
  **Implants · Session Graph · Hosts** across the top half and everything else as tabs
  across the bottom: **Sliver Console · Listeners · Hosted Files · Builds ·
  Armory · Loot · Credentials · Pivoting · Screenshots · Event Log**. Tab titles carry
  live counts.
- **Layout is remembered** — the dock arrangement, graph node positions (stored relative
  to the graph pane, so they survive window resizes), listener presets, host notes and
  the screenshot gallery persist across restarts (see *Settings & data*).
- **Interactive tabs open in the bottom pane** — consoles, shells, file/process browsers,
  registry/services, modules, screenshots and beacon-task views appear below.
- **Dark and light themes** — toggle with ☀/☾ in the toolbar or in ⚙ Settings.
- **New-callback alerts** — a toast and a window/taskbar flash when a new session or
  beacon checks in (and a critical alert if a DNS canary fires). Toggle in Settings.
- **Multiplayer presence** — the toolbar shows which operators are online (👥 menu).
- **Confirmations** on destructive actions (kill session/process/listener, delete files,
  registry writes, removing beacons/builds/profiles/loot/creds).

### Implants (sessions + beacons) & the host graph
- **Live dashboard** — a single **Implants** table listing sessions *and* beacons, with a
  **Type** column (session / beacon) telling them apart. Auto-refreshes and reacts to the
  server event stream: transport and OS badges, last-seen colouring, a **NEW** badge for
  fresh callbacks, a **PID** column (the implant's process ID), and an **Activity** column
  showing when a session last checked in (clock time; *Seen* gives how long ago) or, for a
  beacon, the next check-in, interval/jitter and pending-task count. Elevated users are
  highlighted.
- **Double-click** a row to interact; **right-click** for the action menu (hovering a row
  shows this hint in the status bar) (Interact,
  Shell, Modules, File browser, Process browser, Screenshot, Windows → Registry /
  Services, Pivoting, Host record, Rename, Copy ID, Kill / Remove); the menu adapts to the
  row's type — sessions offer **Interactive shell**, **Ping** (round trip through the C2
  channel) and **Close session** (ends the live session; a beacon that opened it keeps
  checking in); beacons offer **Task history**, **Reconfigure interval**, **Open
  interactive session** (the beacon starts a live session over its active C2 at its next
  check-in) and **Refresh record**. **Modules** is a hover submenu: it lists the modules that
  apply to the implant's OS (quick actions run straight away, the rest open the Modules
  tab on that page). Use **Open Modules tab** in the submenu for the full tab.
- **Session Graph** — each implant is a compact chip: a status dot and its name, with the
  outline coloured by permission level (red = SYSTEM/High/root, blue = user, grey =
  beacon; a hollow red dot = dead). **Hover** a chip for a details card — type, host,
  user, integrity, OS, transport, remote address, PID, last check-in, and for beacons the
  interval, next check-in and pending tasks — and its edge lights up while the others dim.
  Hosts talking straight to the server connect to the **C2** hub (*egress*); **chained
  implants** (TCP / named-pipe pivots) hang off their parent with a dashed **pivot** edge.
  Edges are labelled with the transport. Drag chips to arrange them (positions persist);
  click to open a console. Cards are spread so they never overlap.
- **Live / dead status** — Sliver's own verdict, shown as a **Status** column in the
  Implants table and as *live* / *dead* on each graph card (dead cards fade,
  with a red outline and a dashed red link; hover for last-seen). Lists re-poll every 30 s
  because Sliver only re-evaluates "dead" when they are fetched. An implant killed
  without being told to exit (e.g. its process was killed) stays listed as dead until you
  remove it.
- **Rename** sessions and beacons in place.
- **Beacon reconfigure** — change a live beacon's check-in interval and jitter without
  rebuilding (queued as a task; applied at the next check-in).

### Hosts & IOCs
The **Hosts** tab is the server's per-host inventory (independent of live implants):
hostname, OS, locale, first contact, live implants per host, and open IOCs. Selecting a
host shows its implants (click to interact), **operator notes** (saved locally), and an
**IOC / cleanup checklist** — artifacts left on the host (e.g. uploads tracked as IOCs);
mark each **✓ cleaned** once removed. Host records can be removed.

### Interaction
- **Interactive shells** over the Sliver tunnel data plane, with a built-in VT100
  terminal — PTY or raw, live keystrokes, Ctrl-C, resize.
- **Interaction console** per session/beacon: `ls`, `cd`, `pwd`, `ps`, `procs` (process
  browser), `cp`, `mv`, `chmod`, `mkdir`, `rm [-r]`, `download`, `upload` (tracked as an
  IOC), `screenshot`, `clear`, `help`, or run any program (`execute`).
- **Console quality-of-life** — **↑/↓ command history**, timestamps on commands and
  results, and your operator name in the prompt.
- **Beacon consoles** show a status strip (interval, next check-in, pending tasks) and
  **print task results automatically** as they complete — no manual fetching.
- **Command autocomplete** in the consoles — a completion popup with descriptions;
  **Tab** or click accepts (Tab stays in the input, never jumps to *Run*), **↑/↓** move the
  highlight, **Enter** runs. The Sliver
  Console is context-aware (verbs first, then live session/beacon/job ids). *The
  interactive shell deliberately has no autocomplete* — it's a real shell on the target.

### Process browser
Per-implant process list as a **table or tree** (children under parents), filterable by
name / PID / owner / command line, with the implant's own process highlighted and
privileged owners (SYSTEM/root) marked. Right-click a process: **copy PID / command
line**, **kill** or **force kill** (confirmed), and on Windows **migrate into** or
**impersonate the owner**.

### Sliver Console
The **official `sliver-client`** running in an embedded terminal, so you get the real
Sliver console — every command works exactly as it does in a terminal: the full command
set, colours, Tab completion, ↑/↓ history, Ctrl-C, scrollback (mouse wheel), interactive
sub-shells. It reads the same operator configs (`~/.sliver-client/configs`); with several,
it asks which to use. Click the terminal to give it the keyboard. The toolbar has
**Start/Restart**, **Ctrl-C**, **Copy screen**, and the `sliver-client` path (found on
`PATH`, or set it / *Browse…*). (An earlier GUI-native server console that reimplemented a
subset of commands over the API was removed — the embedded client is a strict superset.)
Install the `sliver-client` that matches your server's version (e.g. copy
the `sliver-client` from your Sliver server host or the official Sliver release).

**Stuck command?** Press **Ctrl-C** (the button or the key). Some commands can't be
cancelled inside `sliver-client` while it waits on the server, such as a build
(`generate`) or `getsystem`. For a minute after Ctrl-C, the toolbar shows a red
**■ Force stop** that kills the client and starts a fresh one. Whatever the server
already started (a build, a task on an implant) carries on. A second Ctrl-C at an idle
prompt exits `sliver-client`, the same as in a terminal; press *Start* to bring it back.

### Local Terminal
The tab directly to the right of **Sliver Console**: an interactive shell on the machine the GUI
runs on, in the same terminal (colours, Tab completion, history, Ctrl-C, scrollback). It
starts in your home folder with your login shell — `$SHELL` (zsh, bash, fish …) on
Linux/macOS, PowerShell (`pwsh`, else Windows PowerShell, else `cmd`) on Windows. The
toolbar's **Shell** menu lists every shell found on the host (`/etc/shells` on
Linux/macOS); picking one, or *Browse…* to any other program, restarts the terminal with it
and is remembered. Also **Start/Restart**, **Ctrl-C** and **Copy screen**.

### Activity logging & the timeline
Everything the GUI logs carries a full timestamp with its **UTC offset**
(`2026-10-28 13:29:39 -06:00`), so entries line up across operators and time zones. Daily
files in `~/.local/share/sliver-gui/logs/` (each switchable in ⚙ Settings → Data):

| File | What |
|---|---|
| `activity-YYYYMMDD.log` | every operator action sent to an implant or the server — console commands, right-click and file-browser actions, modules, tunnels, listeners, builds, hosted files, loot/creds changes — and each implant reply (`result:` / `failed:` + reason). Tagged `[name@host (id)]` or `[server]`. Secrets (make-token passwords, values written to env/registry, credential secrets) are left out; in the Interactive shell tab, a line sent while the shell shows a password prompt is logged as `[hidden input]` — this depends on the prompt being on screen (a non-PTY shell's `read -s -p` prints no prompt, so that input *is* logged). |
| `terminal-YYYYMMDD.log` | command lines entered in the Sliver Console and Local Terminal (below) |
| `events-YYYYMMDD.log` | the Event Log (callbacks, listeners, notices) |

The exported report's **Timeline** merges all three into one chronological table (Time ·
Source · Target · Entry), and a **Beacon tasks** table lists each loaded beacon task with
the server's created / sent / completed times. **⎙ Report → Export timeline (CSV)** writes
the same merged timeline as CSV (with a `unix_time` column) for other tools.

### Terminal command log
Every command line you submit in the **Sliver Console** or **Local Terminal** is logged
for reporting, with a timestamp and which terminal it came from, to
`~/.local/share/sliver-gui/logs/terminal-YYYYMMDD.log`, and listed under **Terminal
commands** in the exported report's timeline:

    2026-10-28 13:12:55 -06:00 [local:bash] operator@workstation:~$ ls /etc | head -2
    2026-10-28 13:13:08 -06:00 [sliver-console] [192.0.2.10] sliver > jobs

The logged line is what the terminal shows when you press Enter: prompt plus command,
including whatever Tab completion or ↑ history filled in. It is read off the screen, and
your keystrokes reach the program exactly as before. So input a program doesn't display —
a `sudo` / `read -s` / SSH password — is never logged, and nothing is logged while a
full-screen program (vim, less, top) is open. Pasting several lines logs each one. Turn it
off under ⚙ Settings → Data.

### Cancelling session commands
In a session console, every request that waits on the implant shows a **running** line
above the input (spinner, elapsed time, **✕ Cancel**); **Esc** cancels the newest. Covers
`execute`/programs, `ls`, `ps`, `cd`, `pwd`, `cp`, `mv`, `rm`, `mkdir`, `chmod`, `grep`,
uploads, downloads, screenshots and the Modules actions (getsystem, execute-assembly,
extensions…). Cancel stops the GUI waiting. Anything the implant already started keeps
running on the target. Beacon requests only queue a task, so there's nothing to cancel
(use *Task history*).

### Post-exploitation modules
A per-implant Modules workspace — the intuitive "load a module" surface. It only offers
what the implant's OS supports:

| Module | Windows | Linux / macOS |
|---|---|---|
| Quick: ifconfig, netstat, env | ✓ | ✓ |
| Quick: whoami, getprivs, getsystem, rev2self, migrate, impersonate, make-token | ✓ | — |
| *.NET Assembly* (`execute-assembly`, AMSI/ETW bypass, host process, class/method) | ✓ | — |
| *Sideload* (DLL / `.so` / `.dylib` into a host process) | ✓ | ✓ |
| *Spawn DLL* (reflective DLL) | ✓ | — |
| *BOF* (Beacon Object Files via coff-loader) | ✓ | — |
| *Extensions* — register a native extension and call its exports | ✓ | ✓ (BOF extensions hidden) |
| *WASM* — list, register (`.wasm`) and run WebAssembly extensions with arguments | ✓ | ✓ |
| *Environment* — show all variables, set or unset one in the implant process | ✓ | ✓ |

### Beacon task-history
Per-beacon task table with live state (pending / sent / **completed**), one-click
**view result** (decoded into the beacon console) and **cancel**; beacons can be renamed
or removed.

### File browser
- **Breadcrumb navigation** with back / up / refresh, a go-to-path box, a **Recent
  folders** list and **Mounts** (drives / mount points with free space).
- Right-click a file: **download**, **preview** (text, or a hex dump for binaries),
  **add to loot**, copy path, **rename / move**, **copy**, **chmod**, **chown**
  (Linux/macOS; `user:group` names, optionally recursive), **delete** (confirmed). Double-click a file to preview; click a folder to open it.
- **Search contents** (grep, optionally recursive) with clickable results.
- **Upload** into the current folder, optionally **tracked as an IOC** so it appears in
  the host's cleanup checklist (on by default). **New folder** asks for a name.

### Screenshots & gallery
- Screenshots render inline; every capture is also saved to disk and listed in the
  **Screenshots** gallery per host, with timestamps, notes, zoom, **add to loot** and
  delete.

### Loot & Credentials
- **Loot** — add local files, add remote files (file browser), screenshots; preview
  (text / hex), save to disk, **rename**, remove; search; origin host shown.
- **Credentials** — add / edit / remove; hash-type badges (NTLM, NetNTLMv2, Kerberos,
  DCC2, sha512crypt, …); plaintext vs hash; cracked state; collection tags; origin host;
  search across user / secret / tag / type; click a secret to copy; secrets masked until
  hovered (Settings); multi-select remove; duplicate check on add. A **type filter** asks
  the server for every credential of one hash type; **Edit** reloads the record from the
  server; **Detect** in the editor asks the server to identify a hash (it names
  unambiguous formats such as `$6$` sha512crypt — bare hex like NTLM / MD5 is ambiguous,
  so pick those by hand).

### Windows registry & services
- **Registry browser** (Windows implants) — pick a hive, navigate keys, read values,
  copy paths. Writing a value (REG_SZ / REG_DWORD), creating a subkey and deleting a key
  are available under *Edit* and always ask for confirmation.
- **Services** — every service with status, start type, account and binary path;
  filter, *running only*, right-click for **Details** (full record incl. description),
  start / stop (confirmed), **Remove service** (confirmed; deletes it from the service
  manager — needs an elevated session) or copy.

### Listeners
Start and manage server jobs from the **Listeners** tab / dialog:
- **mTLS**, **HTTP(S)**, **DNS** and **WireGuard** C2 listeners (WG: UDP port, in-tunnel
  comms port, key-exchange port).
- **Stage (TCP)** — generates a Windows/amd64 shellcode stage (encrypted per build) and
  serves it over a TCP stage listener. Validated end-to-end on v1.7.9 (staged Windows
  session: 67 PASS / 0 FAIL / 11 N/A).
- **HTTP(S) → Website** (optional) attaches a hosted-files website so the listener also
  serves those files (see *Hosted files*).
- **HTTPS certificate** (HTTPS ticked): *Sliver self-signed* (default), *Certificate
  files* (PEM cert + key; *Browse…* or **Generate a self-signed certificate**: name/CN,
  extra DNS names / IPs, validity; written to `<data dir>/certs/<name>.crt|.key`, key
  `0600`, SHA-256 fingerprint shown), or *Let's Encrypt* for the Domain (needs public DNS
  and TCP 80). The files are read each time the listener starts, so Edit → Save & restart
  re-uses them. Sliver implants don't pin the listener certificate (C2 traffic is also
  encrypted by Sliver itself), so the certificate isn't built into the implant. Generate
  shows which certificate a picked HTTPS listener presents.
- **Presets** — save a listener configuration by name and load it later.
- **Edit** a running job to view its settings; change any and **Save & restart** stops
  the job and starts it again with the new settings (implants on it reconnect on their next
  attempt). Saving is disabled until something changes. If the new settings fail to start
  (e.g. port in use) the original listener is started again. Sliver's job list only reports
  protocol, port and domains, so the GUI records the full settings of listeners **it**
  starts (keyed by protocol + port, which survives server restarts). Listeners started
  elsewhere open with what Sliver reports and a note listing what to check: bind host;
  website for HTTP(S); tunnel ports for WireGuard; stage C2. mTLS is fully reported.
- **Clone** any running job into the dialog; **Kill** (confirmed).
- **↻ Restart** a job, or **Restart all**, with its current settings (stop + start, as
  Save & restart does). Only listeners whose full settings are known can be restarted this
  way — ones this GUI started, and any mTLS job; for the rest ↻ is greyed out, use ✎ Edit.
  The GUI does not use Sliver's own `RestartJobs` RPC: on v1.7.9 it brings an mTLS job
  back as a broken `http` listener on port 0.
- **WireGuard tunnel ports** (key exchange / comms, defaults 1337 / 8888) live *inside*
  the tunnel; they are not firewall ports, and an implant only connects if it was built
  with exactly the listener's pair. Picking a WG listener in Generate fills them in from a
  GUI-started listener and flags a mismatch (with *Use listener's ports*). For a listener
  started elsewhere, the generator says the ports are unknown; check them under Edit.
- **Host vs. callback address:** a listener's *Host* is the address it binds to on the
  Sliver server (`0.0.0.0` = all interfaces). Domain names belong in the implant's C2
  address (Generate → Listener, e.g. `dataleakwarehouse.com:8888`), which the target
  resolves at run time.

### Hosted files
Host a file for download over your HTTP(S) listeners, built on Sliver's native
*websites* feature — the **Hosted Files** tab:
1. **Choose file…** → the web path (`/<filename>`) and Content-Type are filled in
   (both editable); pick a **website** name (a group of hosted files, created on first
   upload; default `files`) → **Upload & host**. The file is stored on the Sliver server.
2. **Start listener for this website…** opens the listener dialog pre-set to plain HTTP
   with that website attached (or start any HTTP(S) listener with *Website* set).
3. Each hosted file shows its full **download URL** (built from the server address and
   the listener chosen under *Serve via*) with one-click copy of the **URL**, a
   **PowerShell** (`Invoke-WebRequest … -OutFile`) command, or a **curl** command.
   URLs end in `?v=1`: Sliver servers built before May 2026 send website content **twice**
   for URLs without a numeric query parameter (upstream "Duplicate HTML Fix"), which
   corrupts binaries (Windows: "This app can't run on this PC"). The parameter is harmless
   on fixed servers. Prefer the GUI's links, or upgrade the server.
   Sliver's HTTP listener also **cuts any response off after about 60 s**, so slow clients
   get a partial file. Windows PowerShell 5.1's progress bar slows `Invoke-WebRequest`
   enough to hit that on a ~40 MB implant ("The connection was closed unexpectedly"), so the
   copied PS command sets `$ProgressPreference='SilentlyContinue'` and `-UseBasicParsing`.
   Hover a path for Content-Type / SHA-256 / original filename.
4. ⟳ **replaces** a file's content at the same URL; ✎ changes only its **Content-Type**;
   ✕ stops hosting a file; ✕ next to a website removes it and all its files.

Website paths are served by the listener; all other paths still reach the C2 handler.
HTTPS listeners use a self-signed certificate unless one is supplied, so plain HTTP is
the easiest for target-side download tools (the curl command adds `-k` for HTTPS).

### Payload generator
Build session or beacon implants for Windows / Linux / macOS. The dialog reads top-down:

1. **Target OS → Arch → Format.** Only what the OS supports is offered (shellcode and
   service are Windows-only; macOS has no 386).
2. **Listener type** — mTLS, HTTP(S), DNS, WireGuard, TCP pivot or named pipe.
3. **Listener** — pick one the server is already running (mTLS/WG/HTTP/DNS jobs, addressed
   by the server host you're connected to; pivot listeners are read from your sessions,
   ⟳ re-reads them) or type an address.
4. **Only the options that apply:** HTTP C2 profile for HTTP(S), key-exchange / comms ports
   for WireGuard (must match the listener; defaults 1337 / 8888), Donut options for
   shellcode, interval / jitter for beacons.
5. **Advanced** (collapsed unless used): fallback C2s on other transports (tried after the
   listener, in order), canary domains, execution limits.

When the server
finishes compiling, a **Save dialog** asks where to put it (pre-filled with the server's
file name, starting in the last folder you saved to). Cancel and the build stays on the
server — download it later from **Builds → Build history**. Building from a profile and
re-downloading a build prompt the same way.
- **WireGuard:** the tunnel IP is assigned automatically per build. A WG session's
  *remote* address is the in-tunnel IP the server hands out at key exchange
  (`100.64.0.x`), not the target's LAN address.
- **Canary domains** — DNS canaries that alert if the binary is resolved / inspected.
- **Execution limits** (scope guardrails) — hostname, username, domain-joined only, and a
  kill date; the implant exits outside them.
- **Obfuscation** driven by Sliver itself: randomised Go symbols, and for shellcode Donut
  entropy (with encryption, **the bytes differ on every build**) and aPLib compression.
- **Save as profile** — store the configuration on the server for one-click rebuilds.

### Builds
The **Builds** tab collects everything about payloads:
- **Profiles** — saved implant recipes: **Generate** now, **Load in generator** to tweak,
  delete.
- **Build history** — every implant the server has built (target, format, mode, C2):
  **re-download** (regenerate) or delete.
- **Canaries** — DNS canary status (quiet / **TRIGGERED**, first/latest, hit count).
- **HTTP C2 profiles** — list and inspect the server's profiles (user agent, path
  segments, headers, cookies, nonce settings), **export / import as JSON**, and
  **Use in generator**.

### Pivoting
A dedicated workspace with three sections:
- **Tunnels** — **SOCKS5 proxy** (local listener, the implant runs the SOCKS server),
  **local port-forward** to a `host:port` reachable from the target, and **reverse
  port-forward**; active tunnels listed with live connection counts and stop. Below that,
  **Reverse port-forwards on this implant (server view)** lists every rportfwd the server
  has open on the selected session — including ones other operators started — with stop.
- **Implant chaining** — start **TCP** or **named-pipe pivot listeners** on a session so
  implants that can't reach the server relay through it. The panel shows the exact C2 URL
  to build the downstream implant with (copy, or **Open generator** pre-filled); listeners
  show their connected peers. Chains appear on the Session Graph.
- **WireGuard** — for sessions on the wg transport: in-tunnel **SOCKS5** and
  **port-forwards** (start / list / stop), and **Export WG client config** (wg-quick file
  for an operator machine).

### Server
The **Server** tab shows what the Sliver server reports about itself:
- **Compile targets** — the OS/arch pairs and output formats the server can build, its
  cross-compilers, and how many more pairs would need one. The generator shows a warning
  when the selected OS / arch / format isn't in this list.
- **External builders** registered with the server.
- **Certificate authorities** and issued **certificates** (CN, type, key, validity), with
  a filter.
- **AI assistant** — configured providers, and saved conversations (view the transcript,
  delete).

### Reporting
- **⎙ Report → Export engagement report** — a Markdown report: summary, hosts, outstanding
  IOCs (as a checklist), host notes, sessions, beacons, listeners, credentials (secrets
  omitted unless you opt in), loot, builds, and the timeline.
- **Export event log (CSV)**, and an optional daily event-log file (Settings).

### Armory
A built-in package browser for the official Sliver armory. Fetches the signed index,
lists all extensions, and installs any of them with one click (download →
**minisign signature verification** → extract to `~/.sliver-client/extensions/`).
Installed extensions appear in each implant's Modules → Extensions panel with a
**Load onto implant** button; BOFs route to the BOF runner.

---

## Requirements

- A recent **stable Rust** toolchain (via [rustup](https://rustup.rs)).
- A C compiler + **CMake** (for `aws-lc-rs`, the TLS crypto backend).
- **Linux:** desktop libraries for `eframe`: `libxkbcommon`, `libwayland` / `libx11`, and
  an OpenGL or Vulkan driver.
- **Sliver Console tab (optional):** a `sliver-client` binary matching the server version.
- **Platforms:** pure Rust + portable crates, so it should build on Linux, Windows and
  macOS (x86_64 and ARM64), but it has only been built and tested on **Linux x86_64**.
  On Windows, use the MSVC toolchain with CMake installed (aws-lc may also need NASM);
  Sliver configs are read from `%USERPROFILE%\.sliver-client\configs\`.
- **No `protoc` needed** — the Sliver protobufs are compiled at build time by the
  pure-Rust [`protox`](https://crates.io/crates/protox).

---

## Build

```bash
cargo build --release
./target/release/sliver-gui
```

If Rust was installed with rustup and isn't on your `PATH`:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
```

---

## Server setup

The GUI is only an operator client — it connects over Sliver's operator gRPC API using
an operator **config profile** (`.cfg`). That profile is a bundle of mTLS certs plus the
server address, and it **can only be minted on the server host** with `sliver-server`,
because signing it requires the server CA key (which lives in the server's database).
There is no client-side or in-GUI way to generate one — this is the key setup step.

Run these **on the Sliver server host**:

```bash
# 1. Start the server in daemon mode (exposes the operator gRPC API).
#    Here --lhost is the SERVER's bind address: 0.0.0.0 = all interfaces.
sliver-server daemon --lhost 0.0.0.0 --lport 31337

# 2. Mint an operator profile. Here --lhost is the address the CLIENT will DIAL,
#    so it must be the server's reachable IP/hostname — never 0.0.0.0.
#    --lport must match the daemon's operator port (31337 by default).
#    --permissions is required on current Sliver (use `all`, or a comma list).
sliver-server operator \
  --name <you> \
  --lhost <server-ip> \
  --lport 31337 \
  --permissions all \
  --save ./<you>.cfg

# 3. Start an implant C2 listener for your payloads to call back to, e.g.
#    from the interactive `sliver-server` console:
#      mtls --lhost 0.0.0.0 --lport 8888
```

> **`--lhost` means two different things.** For `daemon` it's the server's *bind*
> address (`0.0.0.0`). For `operator` it's the address the client *dials* — put the
> server's real IP/DNS name there. The dial address is baked into the `.cfg`, so if the
> server later moves to a new IP you must **re-mint the profile** (certs are tied to the
> operator name, not the IP, so you can also just edit `lhost`/`lport` in the JSON and
> reconnect — no new certs needed).
>
> The interactive-console equivalent of step 2 is
> `new-operator --name <you> --lhost <server-ip> --save <path>`, with
> `multiplayer --lport 31337` to start the operator listener. The standalone
> `sliver-server operator …` form shown above is the non-interactive version, handy for
> scripting over SSH.

Then install the profile on the **operator's machine** (where the GUI runs):

```bash
mkdir -p ~/.sliver-client/configs
cp <you>.cfg ~/.sliver-client/configs/
chmod 600 ~/.sliver-client/configs/<you>.cfg   # it contains your private key
```

The GUI auto-discovers everything in `~/.sliver-client/configs/` on launch (the stock
`sliver` client does too, via `sliver import <you>.cfg`). You can also point the GUI's
**Import config…** button at a `.cfg` elsewhere on disk.

> **Keep `.cfg` files secret** — each one carries an operator private key. Don't commit
> them or share them in the clear.

---

## Usage

1. Launch `sliver-gui`. It lists any profiles in `~/.sliver-client/configs/`; use
   **Import config…** to add one from elsewhere (it is copied into that folder so it is
   still there next launch). Double-click a profile to connect.
2. Select a profile and **Connect**.
3. You land in the workspace: **Implants**, **Session Graph** and **Hosts** up top, the
   rest as tabs below.

**Working with implants**
- **Double-click** a session/beacon row to interact, or **right-click** for the action
  menu; the **Sliver Console** (embedded `sliver-client`) also works (`use <id>`, `shell`).
- Interactive tabs (console, shell, files, processes, registry, services, modules,
  screenshots, beacon tasks) open in the **bottom** pane.
- In a console, **Tab** autocompletes, **↑/↓** recalls history, **Enter** runs. Beacon
  consoles print results automatically when the beacon checks in.
- Drag cards around the **Session Graph**; click one to open its console.

**Listeners & payloads**
- **Listeners** tab → **Start listener** → mTLS / HTTP(S) / DNS / Stage (TCP) / WireGuard.
  Save frequently used setups as **presets**.
- **Generate** (toolbar) → OS/arch/format, C2 endpoints, optional profile/canaries/limits,
  **Build implant** — or **Save as profile** and build later from the **Builds** tab.

**Pivoting**
- **Pivoting → Implant chaining**: start a TCP pivot listener on a session, copy the
  shown `tcppivot://…` C2 into the generator, run the new implant where it can reach that
  session; it appears chained in the Session Graph.

**Reporting & cleanup**
- Upload with *track as IOC* (default), then use **Hosts → IOC / cleanup checklist**
  during teardown. **⎙ Report** exports the engagement summary.

### Settings & data
- ⚙ **Settings**: theme, new-callback toast / window flash, credential masking, daily
  event-log file, **operator activity log**, **terminal command log**, **send GUI errors to my client log on the server** (on by default; they
  land in `~/.sliver/logs/clients/<operator>/sliver-gui_*.log` on the server), reset dock
  layout / graph positions.
- **Environment (dependency check)**: lists the external tools the GUI relies on at
  runtime — `sliver-client` (for the Sliver Console) and `msfvenom` (for staging) — each
  shown as ✓ found (with path + version) or ⚠ not found (with an install hint). If a tool
  isn't on `PATH` — a repo pull or a portable copy — **Browse…** to the binary (or the
  directory holding it) and the GUI remembers it. These are checked where the GUI *runs*,
  not where it's built.
- Settings live in `~/.config/sliver-gui/settings.json`; screenshots and event logs in
  `~/.local/share/sliver-gui/` (`screenshots/`, `logs/`). On Windows/macOS the
  platform's config / data folders are used.

---

## Payload delivery & staging

Sliver has no native "PowerShell implant" format, and its operator gRPC API does not emit
PowerShell. The supported flow this GUI drives is Sliver's own staging:

1. Start an **mTLS** (or HTTP/DNS) listener for the implant to call back to.
2. Start a **Stage (TCP)** listener — the server compiles an encrypted Windows/amd64
   shellcode stage and serves it over TCP.
3. Produce the stager stub outside the GUI. Sliver v1.7.9 removed `generate stager`;
   see the official Sliver documentation for current staging guidance.
4. When the stub runs, it pulls the stage from the stage listener and the implant calls
   back to your C2 listener, appearing in the Implants table.

> The in-memory PowerShell loader stub is generated by Sliver/msfvenom, not by this GUI.

---

## Architecture

```
egui UI thread  ──commands──▶  Tokio worker thread  ──gRPC/mTLS──▶  Sliver server
      ▲                               │
      └────────── updates ◀───────────┘   (live Events stream + on-demand RPCs)
```

| File | Responsibility |
|------|----------------|
| `src/main.rs`   | entry point; installs the `aws_lc_rs` rustls provider |
| `src/tls.rs`    | custom mTLS: CA-pinned verifier (hostname-skipping) + ALPN `h2` |
| `src/client.rs` | async gRPC worker; `Command`/`Update` protocol; tunnel / SOCKS / pivot planes; listeners; generation; headless batteries |
| `src/client/ops.rs` | extended operations (`Command::Op` → `Update::Op`): processes, file ops, builds/profiles, loot/creds writes, hosts/IOCs, pivot listeners, WireGuard, C2 profiles, registry/services, operators, server info / AI history, ping / open-close session / env / chown / rportfwd list / WASM |
| `src/client/battery_ext.rs` | headless checks for the extended operations |
| `src/client/battery_admin.rs` | headless checks for server admin + implant upkeep (certs, compiler, AI, client log, creds lookups, loot rename, hosted-file replace, ping, env, chown, rportfwd list, WASM, services, open/close session) |
| `src/app.rs`    | the egui / egui_dock interface: dock, toolbar, sessions/beacons, consoles, dialogs, graph |
| `src/app/*.rs`  | one file per view: `procs`, `files`, `collect` (loot/creds), `hosts`, `builds`, `c2prof`, `pivots`, `winops` (registry/services), `gallery`, `report`, `server` (Server tab); `ext` (shared state + modals), `kit` (UI building blocks) |
| `src/settings.rs` | persisted settings (JSON) |
| `src/armory.rs` | armory index fetch, minisign verification, package install |
| `src/config.rs` | operator `.cfg` loading |
| `src/theme.rs`  | dark / light palettes and font fallbacks |
| `proto/`        | vendored Sliver `.proto` definitions, compiled by `protox` in `build.rs` |

The UI thread and a Tokio worker communicate via `Command` (tokio mpsc) and `Update`
(crossbeam) enums; newer features use the `Command::Op(Op)` / `Update::Op(OpUpdate)`
pair defined in `src/client/ops.rs`. Shells and port-forwards are multiplexed over one `TunnelData` bidi
stream; SOCKS rides a second `SocksProxy` stream.

---

## Transport notes

For anyone hacking on the transport:

- **Crypto provider:** Sliver's operator CA is ECDSA **P-521 / SHA-512**, so the rustls
  stack uses the **`aws_lc_rs`** provider — `ring` cannot verify P-521.
- **ALPN:** the client must advertise ALPN `h2`, or the gRPC server drops the connection
  after a clean TLS handshake.
- **Lazy tunnels:** grpc-go withholds HTTP/2 response headers until the first client
  frame, so the shared `TunnelData` and `SocksProxy` streams are opened lazily and primed
  with their first frame.

---

## Development toggles

All are no-ops in normal use; set as environment variables on the binary.

| Variable | Effect |
|----------|--------|
| `SLIVER_GUI_DEMO=1` | seed sample data + a connected state for offline UI preview |
| `SLIVER_GUI_TAB=<name>` | focus a tab on launch (`graph`, `hosts`, `beacons`, `pivoting`, `hosting`, `jobs`, `server`, `local`, `builds`, `c2profiles`, `gallery`, `armory`, `loot`, `creds`, `events`, `console`, `cli`); uses the default layout |
| `SLIVER_GUI_OPEN=<view>[:<id prefix\|name>]` | open a per-implant view (`console`, `files`, `procs`, `registry`, `services`, `modules`, `tasks`, `shot`, `pivot`, `chain`, `wg`, `host`) |
| `SLIVER_GUI_CMD=<line[;line…]>` | with `_OPEN`, run console lines through the console dispatcher |
| `SLIVER_GUI_MODAL=<generate[:mtls\|http\|dns\|wg\|tcp\|pipe][:pick]\|listeners\|wglistener\|httpslistener\|editlistener[:name]\|settings\|reconfig\|confirm>` | open a dialog for capture (nothing is submitted) |
| `SLIVER_GUI_GENPICK=<mtls\|wg\|http\|dns\|tcp\|pipe>=<dir>[=<name>]` | build through the generator's listener picker (first running listener of that type); `SLIVER_GUI_GENPICK_OS=<os>`, `SLIVER_GUI_GENPICK_DEBUG=1`, `SLIVER_GUI_GENPICK_OBF=1` (obfuscate symbols), `SLIVER_GUI_GENPICK_MATCH=<label text>` (pick a specific listener) |
| `SLIVER_GUI_HTTPSCERT=<port>` (with `CONNECT_TEST`) | generate a self-signed cert, check a missing key is refused, start an HTTPS listener on it (job left running; kill with `_KILLJOB`) |
| `SLIVER_GUI_CLI_TYPE=<line>` (with `SLIVER_GUI_TAB=cli`) | type a command into the Sliver Console 1.5 s after its prompt appears |
| `SLIVER_GUI_LOCAL_TYPE=<line>` (with `SLIVER_GUI_TAB=local`) | type a command into the Local Terminal once its shell has drawn a prompt |
| `SLIVER_GUI_TIMELINE_CSV=<path.csv>` | with `SLIVER_GUI_SHOT`: also write the merged timeline CSV |
| `SLIVER_GUI_KEYS=<frame>:<text>` | type `text` as real key events, one per frame from `frame` (`\n` Enter, `\t` Tab, `\w` pause 60 frames); pair with `SLIVER_GUI_INPUT` to click a terminal first |
| `SLIVER_GUI_CLI_INTERRUPT=<secs>` (with `CLI_TYPE`) | press Ctrl-C that long after the typed command, print the last screen line 4 s later, then force-stop and restart the client |
| `SLIVER_GUI_CONSOLE_RUN=<id prefix>=<line>` (+ `SLIVER_GUI_CONSOLE_CANCEL=<secs>`) | run a line in that session's console once it's listed (and cancel it after N s); prints `[gui] running/finished` |
| `SLIVER_GUI_RELISTEN=<port>` (with `CONNECT_TEST`) | edit-listener round trip on ports *port*…*port*+2: restart in place, move port, taken port → original restored, attach website (`_RELISTEN_SITE`, default `files`); jobs killed afterwards unless `_RELISTEN_KEEP` |
| `SLIVER_GUI_HOSTDL=1` (with `CONNECT_TEST`) | hosted-file download integrity: throwaway site + HTTP listener on :9446, byte-compare small and 6 MB files; `SLIVER_GUI_HOSTDL_HOLD=<secs>` uses a 40 MB file and keeps the site up that long so another host can download it |
| `SLIVER_GUI_BUILDINFO=<name filter>` (+ `SLIVER_GUI_REGEN=<build>=<dir>`, `SLIVER_GUI_RMBUILDS=<a,b>`) (with `CONNECT_TEST`) | print build configs, hosted website contents and jobs; re-download one build; delete test builds |
| `SLIVER_GUI_SHOTDEL=<n>` | delete the selected gallery capture after *n* gallery frames (regression check for the delete crash) |
| `SLIVER_GUI_GUIGEN=<profile>=<dir>[=<wg host:port>]` | build through the GUI generate path from a saved profile |
| `SLIVER_GUI_REPORT=<path.md>` | with `_SHOT`, also write the engagement report |
| `SLIVER_GUI_HOME=<dir>` | use an isolated settings/data directory |
| `SLIVER_GUI_SHOT=/path.png` [`SLIVER_GUI_SHOT_FRAMES=<n>`] | render a few frames, save a screenshot, exit |
| `SLIVER_GUI_INPUT="<frame>:<m\|l\|r>:<x>,<y>;…"` | scripted pointer move / left-click / right-click at a frame number (pair with `SLIVER_GUI_SHOT` to capture menus) |
| `SLIVER_GUI_AUTOCONNECT=<label\|index>` | connect on launch |
| `SLIVER_GUI_CONNECT_TEST=<cfg>` | headless connect self-test (prints version/sessions/beacons/jobs) |
| `SLIVER_GUI_SESSION=<auto\|id\|name>` / `SLIVER_GUI_BEACON=<…>` | run the headless session / beacon battery (incl. extended checks) |
| `SLIVER_GUI_WINCHECKS=<session>` | read-only Windows registry/services checks |
| `SLIVER_GUI_SEED=1\|rm` [`SLIVER_GUI_SEED_SESSION=<id>`] | add / remove sample creds, loot, a profile and an IOC upload |
| `SLIVER_GUI_HOSTRMTEST=<hostname>` | delete one host record (verifies host removal) |
| `SLIVER_GUI_PIVOT_LISTEN=<session>=<bind>[=pipe]` | start a pivot listener and leave it running |
| `SLIVER_GUI_START_WG=<udp port>` | start a WireGuard listener |
| `SLIVER_GUI_RMBEACONS=<1\|id[,id]>` | remove all / specific beacon records |
| `SLIVER_GUI_START_MTLS=<port>` | start an mTLS listener |
| `SLIVER_GUI_STAGE=<port>[=<c2 host:port>]` | start a TCP stage listener |
| `SLIVER_GUI_KILLJOB=<id[,id]>` | kill jobs by id |
| `SLIVER_GUI_GEN=1` (+ `_OS`/`_ARCH`/`_LHOST`/`_SAVE`/`_NAME`, `_BEACON=1`+`_INTERVAL`, `_FORMAT=shellcode`+`_ENTROPY`, `_C2=<full url>`) | generate an implant (`_C2` accepts `mtls://`, `wg://`, `tcppivot://`, `namedpipe://`, `https://`) |
| `SLIVER_GUI_AUTOSHELL=1` / `_AUTOBEACON=1` | open a shell / beacon-tasks tab on the first implant |
| `SLIVER_GUI_AUTOSOCKS=<bind>` / `_AUTOPORTFWD=<bind>=<host:port>` | start a SOCKS5 proxy / local port-forward |
| `SLIVER_GUI_ARMORY_TEST=1` | headless armory index/install self-test |

---

## Security

This is offensive-security tooling intended for **authorized** engagements, lab use, and
research. The payload generation and in-memory delivery stubs it references are produced
by Sliver / msfvenom; this client orchestrates the framework's own capabilities. Use it
only against systems you own or are explicitly authorized to test.
