"""
homelink — service management CLI.

Commands
--------
homelink status     Show daemon status
homelink start      Start daemon
homelink stop       Stop daemon
homelink restart    Restart daemon
homelink install    Install systemd service
homelink remove     Remove service
homelink logs       Tail service logs
homelink devices    List known/approved devices
homelink pair       Start pairing workflow
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel
from rich.text import Text

from homelink import __version__
from homelink.config.manager import ConfigManager, DEFAULT_CONFIG_DIR

console = Console()
err_console = Console(stderr=True)


def _config_mgr(config_dir: str | None) -> ConfigManager:
    return ConfigManager(config_dir or DEFAULT_CONFIG_DIR)


@click.group()
@click.version_option(__version__, prog_name="homelink")
@click.option("--config-dir", "-c", default=None, help="Config directory (default: ~/.homelink)")
@click.pass_context
def cli(ctx, config_dir):
    """HomeLink — secure self-hosted remote access. No VPS. No cost."""
    ctx.ensure_object(dict)
    ctx.obj["config_dir"] = config_dir


# ------------------------------------------------------------------ #
# status                                                               #
# ------------------------------------------------------------------ #

@cli.command()
@click.pass_context
def status(ctx):
    """Show daemon and transport status."""
    mgr = _config_mgr(ctx.obj["config_dir"])
    if not mgr.is_initialized():
        err_console.print("[red]HomeLink not initialized. Run: python init.py[/red]")
        sys.exit(1)

    try:
        cfg = mgr.load_config()
    except Exception as e:
        err_console.print(f"[red]Config error: {e}[/red]")
        sys.exit(1)

    from homelink.service.installer import ServiceInstaller
    installer = ServiceInstaller(mgr.config_dir)
    svc_status = installer.status()
    running = svc_status["active"]

    panel_lines = [
        f"[bold]Device ID:[/bold]    [cyan]{cfg.device_id}[/cyan]",
        f"[bold]Device Name:[/bold]  {cfg.device_name}",
        f"[bold]Service:[/bold]      {'[green]running[/green]' if running else '[red]stopped[/red]'}",
        f"[bold]Installed:[/bold]    {'yes' if svc_status['installed'] else 'no'}",
        f"[bold]Telegram:[/bold]     {'[green]configured[/green]' if cfg.telegram.enabled else '[yellow]not configured[/yellow]'}",
        f"[bold]P2P:[/bold]          {'[green]enabled[/green]' if cfg.p2p.enabled else '[yellow]disabled[/yellow]'}",
        f"[bold]Config dir:[/bold]   {cfg.config_dir}",
    ]
    console.print(Panel("\n".join(panel_lines), title="[bold blue]HomeLink Status[/bold blue]", border_style="blue"))


# ------------------------------------------------------------------ #
# start / stop / restart                                               #
# ------------------------------------------------------------------ #

@cli.command()
@click.pass_context
def start(ctx):
    """Start the HomeLink daemon."""
    from homelink.service.installer import ServiceInstaller
    mgr = _config_mgr(ctx.obj["config_dir"])
    installer = ServiceInstaller(mgr.config_dir)
    if installer.start():
        console.print("[green]✓[/green] HomeLink daemon started")
    else:
        err_console.print("[red]Failed to start daemon[/red]")
        sys.exit(1)


@cli.command()
@click.pass_context
def stop(ctx):
    """Stop the HomeLink daemon."""
    from homelink.service.installer import ServiceInstaller
    mgr = _config_mgr(ctx.obj["config_dir"])
    installer = ServiceInstaller(mgr.config_dir)
    if installer.stop():
        console.print("[yellow]●[/yellow] HomeLink daemon stopped")
    else:
        err_console.print("[red]Failed to stop daemon[/red]")


@cli.command()
@click.pass_context
def restart(ctx):
    """Restart the HomeLink daemon."""
    from homelink.service.installer import ServiceInstaller
    mgr = _config_mgr(ctx.obj["config_dir"])
    installer = ServiceInstaller(mgr.config_dir)
    if installer.restart():
        console.print("[green]✓[/green] HomeLink daemon restarted")
    else:
        err_console.print("[red]Failed to restart daemon[/red]")


# ------------------------------------------------------------------ #
# install / remove                                                     #
# ------------------------------------------------------------------ #

@cli.command()
@click.pass_context
def install(ctx):
    """Install systemd user service."""
    from homelink.service.installer import ServiceInstaller
    mgr = _config_mgr(ctx.obj["config_dir"])
    installer = ServiceInstaller(mgr.config_dir)
    if installer.install():
        console.print("[green]✓[/green] Service installed")
        console.print("Run [bold]homelink start[/bold] to start, or reboot for auto-start")
    else:
        err_console.print("[red]Service installation failed[/red]")
        sys.exit(1)


@cli.command()
@click.pass_context
def remove(ctx):
    """Remove systemd service."""
    from homelink.service.installer import ServiceInstaller
    mgr = _config_mgr(ctx.obj["config_dir"])
    if click.confirm("Remove HomeLink service?"):
        installer = ServiceInstaller(mgr.config_dir)
        installer.remove()
        console.print("[yellow]Service removed[/yellow]")


# ------------------------------------------------------------------ #
# logs                                                                 #
# ------------------------------------------------------------------ #

@cli.command()
@click.option("--lines", "-n", default=50, help="Number of log lines")
@click.option("--audit", is_flag=True, help="Show audit log")
@click.pass_context
def logs(ctx, lines, audit):
    """Show recent log entries."""
    mgr = _config_mgr(ctx.obj["config_dir"])
    try:
        cfg = mgr.load_config()
    except Exception as e:
        err_console.print(f"[red]{e}[/red]")
        sys.exit(1)

    import subprocess
    log_dir = Path(cfg.logging.log_dir)
    log_file = log_dir / ("audit.log" if audit else "homelink.log")

    if not log_file.exists():
        console.print(f"[yellow]No log file yet: {log_file}[/yellow]")
        return

    result = subprocess.run(["tail", f"-n{lines}", str(log_file)], capture_output=True, text=True)
    console.print(result.stdout)


# ------------------------------------------------------------------ #
# devices                                                              #
# ------------------------------------------------------------------ #

@cli.command()
@click.pass_context
def devices(ctx):
    """List known devices."""
    mgr = _config_mgr(ctx.obj["config_dir"])
    devs = mgr.load_devices()
    if not devs:
        console.print("[yellow]No devices registered[/yellow]")
        return

    t = Table(title="Registered Devices", box=box.ROUNDED)
    t.add_column("Device ID", style="cyan")
    t.add_column("Name")
    t.add_column("Approved", style="green")
    t.add_column("Fingerprint")

    for did, info in devs.items():
        approved = "✓" if info.get("approved") else "✗"
        fp = info.get("fingerprint", "n/a")
        t.add_row(did, info.get("name", "?"), approved, fp)

    console.print(t)


# ------------------------------------------------------------------ #
# pair                                                                 #
# ------------------------------------------------------------------ #

@cli.command()
@click.pass_context
def pair(ctx):
    """Start device pairing workflow."""
    console.print("[bold]Device Pairing[/bold]")
    console.print("Run [cyan]homectl pair[/cyan] on the remote device to get a pairing code.")
    console.print("Pairing requests appear in your Telegram chat for approval.")
    console.print("\nTo manually approve a pending device:")
    console.print("  Send [cyan]/approve <device_id>[/cyan] in your Telegram bot chat")


# ------------------------------------------------------------------ #
# reconfigure-telegram                                                 #
# ------------------------------------------------------------------ #

@cli.command("reconfigure-telegram")
@click.pass_context
def reconfigure_telegram(ctx):
    """Update Telegram bot token and chat ID."""
    import asyncio, aiohttp, getpass

    mgr = _config_mgr(ctx.obj["config_dir"])
    if not mgr.is_initialized():
        err_console.print("[red]HomeLink not initialized. Run: python init.py[/red]")
        import sys; sys.exit(1)

    cfg = mgr.load_config()

    console.print("[bold]Current Telegram config:[/bold]")
    console.print(f"  Bot token: {'set' if cfg.telegram.bot_token else '[red]not set[/red]'}")
    console.print(f"  Chat ID:   {cfg.telegram.chat_id or '[red]not set[/red]'}")
    console.print("")

    bot_token = click.prompt("New bot token (Enter to keep current)", default=cfg.telegram.bot_token)
    chat_id   = click.prompt("New chat ID (Enter to keep current)",   default=cfg.telegram.chat_id)

    async def _verify(token, cid):
        base = f"https://api.telegram.org/bot{token}"
        async with aiohttp.ClientSession() as s:
            async with s.get(f"{base}/getMe", timeout=aiohttp.ClientTimeout(total=10)) as r:
                d = await r.json()
                if not d.get("ok"):
                    return False, f"Token rejected: {d.get('description','')}"
                bot_name = d["result"].get("username", "?")
            async with s.post(
                f"{base}/sendMessage",
                json={"chat_id": cid, "text": "🔗 HomeLink Telegram reconfigured!", "disable_notification": True},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as r:
                d = await r.json()
                if not d.get("ok"):
                    return False, f"Bot @{bot_name} OK, but chat_id failed: {d.get('description','')}"
        return True, f"Bot @{bot_name} connected — message sent"

    ok_result, msg = asyncio.run(_verify(bot_token, chat_id))
    if ok_result:
        console.print(f"[green]✓[/green] {msg}")
        cfg.telegram.bot_token = bot_token
        cfg.telegram.chat_id   = chat_id
        cfg.telegram.enabled   = True
        mgr.save_config(cfg)
        console.print("[green]✓[/green] Config saved. Restart daemon: [bold]homelink restart[/bold]")
    else:
        err_console.print(f"[red]✗ Verification failed:[/red] {msg}")
        if click.confirm("Save config anyway?"):
            cfg.telegram.bot_token = bot_token
            cfg.telegram.chat_id   = chat_id
            cfg.telegram.enabled   = True
            mgr.save_config(cfg)
            console.print("[yellow]Config saved (unverified)[/yellow]")
