"""
homectl — remote operations CLI.

Commands
--------
homectl status              Show remote device status
homectl ls <path>           List remote directory
homectl get <remote> <local>    Download file
homectl put <local> <remote>    Upload file
homectl rm <remote>         Delete remote file
homectl mkdir <remote>      Create remote directory
homectl exec <command>      Execute allowed remote command
homectl logs [-n N]         Show remote logs
homectl devices             List devices
homectl pair                Initiate pairing
homectl tree <path>         Recursive directory listing
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TransferSpeedColumn
from rich import box

from homelink import __version__
from homelink.config.manager import ConfigManager, DEFAULT_CONFIG_DIR

console = Console()
err = Console(stderr=True)


def _require_config(config_dir: str | None) -> ConfigManager:
    mgr = ConfigManager(config_dir or DEFAULT_CONFIG_DIR)
    if not mgr.is_initialized():
        err.print("[red]HomeLink not initialized. Run: python init.py[/red]")
        sys.exit(1)
    return mgr


@click.group()
@click.version_option(__version__, prog_name="homectl")
@click.option("--config-dir", "-c", default=None)
@click.option("--device", "-d", default=None, help="Target device ID (default: first approved device)")
@click.pass_context
def ctl(ctx, config_dir, device):
    """homectl — control a remote HomeLink device."""
    ctx.ensure_object(dict)
    ctx.obj["config_dir"] = config_dir
    ctx.obj["device"] = device


# ------------------------------------------------------------------ #
# status                                                               #
# ------------------------------------------------------------------ #

@ctl.command()
@click.pass_context
def status(ctx):
    """Show remote device status."""
    asyncio.run(_status(ctx))


async def _status(ctx):
    mgr = _require_config(ctx.obj["config_dir"])
    cfg = mgr.load_config()
    console.print(f"[bold]Local device:[/bold] [cyan]{cfg.device_id}[/cyan] ({cfg.device_name})")

    devs = mgr.load_devices()
    if not devs:
        console.print("[yellow]No remote devices paired[/yellow]")
        return

    for did, info in devs.items():
        approved = "[green]approved[/green]" if info.get("approved") else "[red]pending[/red]"
        console.print(f"  Peer: [cyan]{did}[/cyan] ({info.get('name','?')}) — {approved}")


# ------------------------------------------------------------------ #
# ls                                                                   #
# ------------------------------------------------------------------ #

@ctl.command()
@click.argument("path", default="~")
@click.option("--long", "-l", is_flag=True, help="Long listing format")
@click.pass_context
def ls(ctx, path, long):
    """List remote directory."""
    asyncio.run(_ls(ctx, path, long))


async def _ls(ctx, path: str, long: bool):
    client = await _make_client(ctx)
    result = await client.send_request({"type": "ls_request", "path": path})
    if result.get("error"):
        err.print(f"[red]{result['error']}[/red]")
        return
    entries = result.get("entries", [])
    if long:
        t = Table(box=box.SIMPLE)
        t.add_column("Type", style="dim")
        t.add_column("Size", justify="right")
        t.add_column("Mode")
        t.add_column("Name")
        for e in entries:
            icon = "📁" if e["type"] == "dir" else "📄"
            size = f"{e['size']:,}" if e["type"] == "file" else "-"
            t.add_row(icon, size, e.get("mode", ""), e["name"])
        console.print(t)
    else:
        for e in entries:
            icon = "📁 " if e["type"] == "dir" else "   "
            console.print(f"{icon}{e['name']}")


# ------------------------------------------------------------------ #
# get (download)                                                       #
# ------------------------------------------------------------------ #

@ctl.command()
@click.argument("remote")
@click.argument("local", default=".")
@click.pass_context
def get(ctx, remote, local):
    """Download file from remote device."""
    asyncio.run(_get(ctx, remote, local))


async def _get(ctx, remote: str, local: str):
    client = await _make_client(ctx)
    local_path = Path(local)
    if local_path.is_dir():
        local_path = local_path / Path(remote).name

    console.print(f"Downloading [cyan]{remote}[/cyan] → [green]{local_path}[/green]")
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.percentage:>3.0f}%"),
        TransferSpeedColumn(),
    ) as progress:
        task = progress.add_task("Downloading...", total=100)
        def on_progress(session):
            progress.update(task, completed=session.progress)
        await client.download_file(remote, local_path, progress_cb=on_progress)

    console.print(f"[green]✓[/green] Download complete: {local_path}")


# ------------------------------------------------------------------ #
# put (upload)                                                         #
# ------------------------------------------------------------------ #

@ctl.command()
@click.argument("local")
@click.argument("remote")
@click.pass_context
def put(ctx, local, remote):
    """Upload file to remote device."""
    asyncio.run(_put(ctx, local, remote))


async def _put(ctx, local: str, remote: str):
    local_path = Path(local).expanduser()
    if not local_path.exists():
        err.print(f"[red]File not found: {local}[/red]")
        sys.exit(1)

    client = await _make_client(ctx)
    size_mb = local_path.stat().st_size / 1_048_576
    console.print(f"Uploading [green]{local}[/green] ({size_mb:.1f} MB) → [cyan]{remote}[/cyan]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.percentage:>3.0f}%"),
        TransferSpeedColumn(),
    ) as progress:
        task = progress.add_task("Uploading...", total=100)
        def on_progress(session):
            progress.update(task, completed=session.progress)
        await client.upload_file(local_path, remote, progress_cb=on_progress)

    console.print(f"[green]✓[/green] Upload complete")


# ------------------------------------------------------------------ #
# exec                                                                 #
# ------------------------------------------------------------------ #

@ctl.command("exec")
@click.argument("command", nargs=-1)
@click.option("--timeout", "-t", default=60, help="Timeout in seconds")
@click.pass_context
def exec_cmd(ctx, command, timeout):
    """Execute command on remote device."""
    if not command:
        err.print("[red]No command specified[/red]")
        sys.exit(1)
    cmd_str = " ".join(command)
    asyncio.run(_exec(ctx, cmd_str, timeout))


async def _exec(ctx, command: str, timeout: int):
    client = await _make_client(ctx)
    console.print(f"[dim]$ {command}[/dim]")
    result = await client.send_request({
        "type": "exec_request",
        "command": command,
        "timeout": timeout,
    })

    if result.get("denied"):
        err.print(f"[red]Permission denied:[/red] {result.get('deny_reason', '')}")
        sys.exit(1)

    if result.get("timed_out"):
        err.print("[yellow]Command timed out[/yellow]")

    if result.get("stdout"):
        console.print(result["stdout"], end="")
    if result.get("stderr"):
        err.print(result["stderr"], end="")

    rc = result.get("returncode", 0)
    if rc != 0:
        sys.exit(rc)


# ------------------------------------------------------------------ #
# rm                                                                   #
# ------------------------------------------------------------------ #

@ctl.command()
@click.argument("remote")
@click.option("--force", "-f", is_flag=True)
@click.pass_context
def rm(ctx, remote, force):
    """Delete file on remote device."""
    if not force and not click.confirm(f"Delete remote file '{remote}'?"):
        return
    asyncio.run(_rm(ctx, remote))


async def _rm(ctx, remote: str):
    client = await _make_client(ctx)
    result = await client.send_request({"type": "rm_request", "path": remote})
    if result.get("error"):
        err.print(f"[red]{result['error']}[/red]")
        sys.exit(1)
    console.print(f"[green]✓[/green] Deleted: {remote}")


# ------------------------------------------------------------------ #
# mkdir                                                                #
# ------------------------------------------------------------------ #

@ctl.command()
@click.argument("remote")
@click.pass_context
def mkdir(ctx, remote):
    """Create directory on remote device."""
    asyncio.run(_mkdir(ctx, remote))


async def _mkdir(ctx, remote: str):
    client = await _make_client(ctx)
    result = await client.send_request({"type": "mkdir_request", "path": remote})
    if result.get("error"):
        err.print(f"[red]{result['error']}[/red]")
        sys.exit(1)
    console.print(f"[green]✓[/green] Created: {remote}")


# ------------------------------------------------------------------ #
# tree                                                                 #
# ------------------------------------------------------------------ #

@ctl.command()
@click.argument("path", default="~")
@click.pass_context
def tree(ctx, path):
    """Recursive directory listing on remote device."""
    asyncio.run(_tree(ctx, path))


async def _tree(ctx, path: str):
    client = await _make_client(ctx)
    result = await client.send_request({"type": "tree_request", "path": path})
    if result.get("error"):
        err.print(f"[red]{result['error']}[/red]")
        return
    _print_tree(result.get("tree", {}))


def _print_tree(node: dict, prefix: str = "", is_last: bool = True):
    connector = "└── " if is_last else "├── "
    icon = "📁 " if node.get("type") == "dir" else ""
    console.print(f"{prefix}{connector}{icon}{node.get('name','?')}")
    children = node.get("children", [])
    child_prefix = prefix + ("    " if is_last else "│   ")
    for i, child in enumerate(children):
        _print_tree(child, child_prefix, i == len(children) - 1)


# ------------------------------------------------------------------ #
# pair                                                                 #
# ------------------------------------------------------------------ #

@ctl.command()
@click.pass_context
def pair(ctx):
    """Initiate device pairing with a home device."""
    asyncio.run(_pair(ctx))


async def _pair(ctx):
    mgr = _require_config(ctx.obj["config_dir"])
    import secrets
    code = secrets.token_hex(3).upper()   # 6-char hex code
    cfg = mgr.load_config()
    cfg.pairing_code = code
    mgr.save_config(cfg)

    console.print(f"\n[bold]Pairing Code:[/bold] [cyan bold]{code}[/cyan bold]\n")
    console.print("On your home machine, approve this device:")
    console.print(f"  Send [cyan]/approve {cfg.device_id}[/cyan] in your Telegram bot chat")
    console.print(f"\nOr scan the QR code:\n")
    _print_qr(f"homelink-pair:{cfg.device_id}:{code}")


def _print_qr(data: str):
    try:
        import qrcode
        qr = qrcode.QRCode(border=1)
        qr.add_data(data)
        qr.make(fit=True)
        qr.print_ascii(invert=True)
    except Exception:
        console.print(f"[dim]QR data: {data}[/dim]")


# ------------------------------------------------------------------ #
# logs                                                                 #
# ------------------------------------------------------------------ #

@ctl.command()
@click.option("--lines", "-n", default=20)
@click.pass_context
def logs(ctx, lines):
    """Show local HomeLink logs."""
    mgr = _require_config(ctx.obj["config_dir"])
    try:
        cfg = mgr.load_config()
    except Exception as e:
        err.print(f"[red]{e}[/red]")
        sys.exit(1)
    import subprocess
    log_file = Path(cfg.logging.log_dir) / "homelink.log"
    if not log_file.exists():
        console.print("[yellow]No logs yet[/yellow]")
        return
    result = subprocess.run(["tail", f"-n{lines}", str(log_file)], capture_output=True, text=True)
    console.print(result.stdout)


# ------------------------------------------------------------------ #
# devices                                                              #
# ------------------------------------------------------------------ #

@ctl.command()
@click.pass_context
def devices(ctx):
    """List paired devices."""
    mgr = _require_config(ctx.obj["config_dir"])
    devs = mgr.load_devices()
    if not devs:
        console.print("[yellow]No paired devices[/yellow]")
        return
    t = Table(box=box.ROUNDED)
    t.add_column("ID", style="cyan")
    t.add_column("Name")
    t.add_column("Approved")
    for did, info in devs.items():
        t.add_row(did, info.get("name", "?"), "✓" if info.get("approved") else "✗")
    console.print(t)


# ------------------------------------------------------------------ #
# Client helper                                                        #
# ------------------------------------------------------------------ #

async def _make_client(ctx):
    """Create a RemoteClient for the target device."""
    mgr = _require_config(ctx.obj["config_dir"])
    device_id = ctx.obj.get("device")
    if device_id is None:
        devs = mgr.load_devices()
        approved = [d for d in devs.values() if d.get("approved")]
        if not approved:
            err.print("[red]No approved devices. Run: homectl pair[/red]")
            sys.exit(1)
        device_id = approved[0]["device_id"]

    from homelink.cli.client import RemoteClient
    return RemoteClient(mgr, device_id)
