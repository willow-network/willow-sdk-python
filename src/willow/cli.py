#!/usr/bin/env python3
"""CLI for Willow SDK.

The SDK has no server-side session: every authenticated request is signed
locally with a DID + private key + public key ID via `client.set_identity`.
`willow-cli auth login` therefore just persists those three values to
`~/.willow/config.json`, and subsequent commands re-load them on each
invocation.
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional, Tuple
import click
from .client import WillowClient
from .auth import generate_did
from .types import DidDocument


CONFIG_FILE = Path.home() / ".willow" / "config.json"


def load_config() -> dict:
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            return json.load(f)
    return {}


def save_config(config: dict):
    CONFIG_FILE.parent.mkdir(exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)


def get_identity_or_exit() -> Tuple[str, str, str]:
    """Return (did, private_key, public_key_id) from config, or exit."""
    config = load_config()
    identity = config.get("identity")
    if not identity:
        click.echo("Not authenticated. Run: willow-cli auth login")
        sys.exit(1)
    return identity["did"], identity["private_key"], identity["public_key_id"]


@click.group()
@click.option("--api-url", default="http://localhost:3031", help="Willow API URL")
@click.pass_context
def cli(ctx, api_url):
    """Willow CLI - Interact with Willow from the command line."""
    ctx.ensure_object(dict)
    ctx.obj["api_url"] = api_url


@cli.group()
def did():
    """DID management commands."""
    pass


@did.command()
@click.option("--algorithm", type=click.Choice(["Ed25519", "secp256k1"]), default="Ed25519")
@click.option("--save", is_flag=True, help="Save to config file")
def generate(algorithm, save):
    """Generate a new DID with keypair."""
    did_info = generate_did(algorithm)

    output = {
        "did": did_info["did"],
        "private_key": did_info["private_key"],
        "public_key": did_info["public_key"],
        "public_key_id": did_info["public_key_id"],
        "algorithm": did_info["algorithm"],
    }

    if save:
        config = load_config()
        config["identity"] = {
            "did": output["did"],
            "private_key": output["private_key"],
            "public_key_id": output["public_key_id"],
        }
        save_config(config)
        click.echo("Identity saved to config file")

    click.echo(json.dumps(output, indent=2))


@did.command()
@click.argument("did_file", type=click.File("r"))
@click.pass_context
def register(ctx, did_file):
    """Register a DID document."""

    async def _register():
        did_doc_data = json.load(did_file)
        did_doc = DidDocument(**did_doc_data)

        async with WillowClient(ctx.obj["api_url"]) as client:
            result = await client.register_did(did_doc)
            click.echo(f"DID registered successfully: {result.id}")

    asyncio.run(_register())


@cli.group()
def auth():
    """Authentication commands.

    The SDK has no server session: signing happens per-request locally. These
    commands just persist the DID + private key + public key ID to
    ~/.willow/config.json so other CLI commands can load and use them.
    """
    pass


@auth.command()
@click.option("--did", "did_arg", help="DID to authenticate with")
@click.option("--key", "key_arg", help="Private key hex")
@click.option("--key-id", "key_id_arg", help="Public key ID")
def login(did_arg, key_arg, key_id_arg):
    """Save identity (DID + key + key-id) to ~/.willow/config.json."""
    config = load_config()
    existing = config.get("identity") or {}

    did_val = did_arg or existing.get("did")
    key_val = key_arg or existing.get("private_key")
    key_id_val = key_id_arg or existing.get("public_key_id")

    if not (did_val and key_val and key_id_val):
        click.echo("Need --did, --key, and --key-id (or run `willow-cli did generate --save` first).")
        sys.exit(1)

    config["identity"] = {
        "did": did_val,
        "private_key": key_val,
        "public_key_id": key_id_val,
    }
    save_config(config)
    click.echo(f"Identity saved: {did_val}")


@auth.command()
def logout():
    """Clear saved identity."""
    config = load_config()
    if "identity" in config:
        del config["identity"]
        save_config(config)
        click.echo("Identity cleared")
    else:
        click.echo("No saved identity")


@auth.command()
def status():
    """Check whether an identity is saved."""
    config = load_config()
    if "identity" in config:
        click.echo(f"Saved identity: {config['identity']['did']}")
    else:
        click.echo("No saved identity")


@cli.group()
def data():
    """Data operations."""
    pass


@data.command()
@click.argument("subgrove_id")
@click.argument("data_file", type=click.File("r"))
@click.pass_context
def store(ctx, subgrove_id, data_file):
    """Store data in a subgrove. DATA_FILE is JSON (or '-' for stdin)."""

    async def _store():
        did_val, key_val, key_id_val = get_identity_or_exit()
        data_dict = json.load(data_file)

        async with WillowClient(ctx.obj["api_url"]) as client:
            client.set_identity(did_val, key_val, key_id_val)
            await client.data.store(subgrove_id, data_dict)
            click.echo(f"Stored {len(data_dict)} items in {subgrove_id}")

    asyncio.run(_store())


@data.command()
@click.argument("subgrove_id")
@click.argument("key")
@click.pass_context
def get(ctx, subgrove_id, key):
    """Get a single item from a subgrove (with proof verification)."""

    async def _get():
        did_val, key_val, key_id_val = get_identity_or_exit()

        async with WillowClient(ctx.obj["api_url"]) as client:
            client.set_identity(did_val, key_val, key_id_val)
            result = await client.data.get(subgrove_id, key)
            click.echo(json.dumps(result, indent=2))

    asyncio.run(_get())


@data.command()
@click.argument("subgrove_id")
@click.argument("key")
@click.argument("data_file", type=click.File("r"))
@click.pass_context
def update(ctx, subgrove_id, key, data_file):
    """Update an item in a subgrove."""

    async def _update():
        did_val, key_val, key_id_val = get_identity_or_exit()
        data_dict = json.load(data_file)

        async with WillowClient(ctx.obj["api_url"]) as client:
            client.set_identity(did_val, key_val, key_id_val)
            await client.data.update(subgrove_id, key, data_dict)
            click.echo(f"Updated {key} in {subgrove_id}")

    asyncio.run(_update())


@data.command()
@click.argument("subgrove_id")
@click.argument("key")
@click.pass_context
def delete(ctx, subgrove_id, key):
    """Delete an item from a subgrove."""

    async def _delete():
        did_val, key_val, key_id_val = get_identity_or_exit()

        async with WillowClient(ctx.obj["api_url"]) as client:
            client.set_identity(did_val, key_val, key_id_val)
            await client.data.delete(subgrove_id, key)
            click.echo(f"Deleted {key} from {subgrove_id}")

    asyncio.run(_delete())


@cli.group()
def proof():
    """Proof operations."""
    pass


@proof.command()
@click.argument("subgrove_id")
@click.argument("key")
@click.pass_context
def get(ctx, subgrove_id, key):
    """Get the Merkle proof for an item."""

    async def _get_proof():
        async with WillowClient(ctx.obj["api_url"]) as client:
            result = await client.proof.get(subgrove_id, key)
            click.echo(json.dumps(result, indent=2))

    asyncio.run(_get_proof())


def main():
    cli(obj={})


if __name__ == "__main__":
    main()
