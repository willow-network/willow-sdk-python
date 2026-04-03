#!/usr/bin/env python3
"""CLI for Willow SDK."""

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional
import click
from .client import WillowClient
from .auth import generate_did
from .types import DidDocument


# Config file for storing credentials
CONFIG_FILE = Path.home() / ".willow" / "config.json"


def load_config() -> dict:
    """Load config from file."""
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            return json.load(f)
    return {}


def save_config(config: dict):
    """Save config to file."""
    CONFIG_FILE.parent.mkdir(exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)


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
        "algorithm": did_info["algorithm"]
    }
    
    if save:
        config = load_config()
        config["current_did"] = output
        save_config(config)
        click.echo("DID saved to config file")
    
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
    """Authentication commands."""
    pass


@auth.command()
@click.option("--did", help="DID to authenticate with")
@click.option("--key", help="Private key hex")
@click.option("--key-id", help="Public key ID")
@click.pass_context
def login(ctx, did, key, key_id):
    """Authenticate and save session."""
    async def _login():
        # Use saved credentials if not provided
        if not all([did, key, key_id]):
            config = load_config()
            if "current_did" in config:
                did = did or config["current_did"]["did"]
                key = key or config["current_did"]["private_key"]
                key_id = key_id or config["current_did"]["public_key_id"]
            else:
                click.echo("No saved credentials. Please provide --did, --key, and --key-id")
                return
        
        async with WillowClient(ctx.obj["api_url"]) as client:
            session = await client.authenticate(did, key, key_id)
            
            # Save session
            config = load_config()
            config["session"] = {
                "did": session.did,
                "token": session.token,
                "expires_at": session.expires_at
            }
            save_config(config)
            
            click.echo(f"Authenticated as: {session.did}")
            click.echo("Session saved to config file")
    
    asyncio.run(_login())


@auth.command()
def logout():
    """Clear saved session."""
    config = load_config()
    if "session" in config:
        del config["session"]
        save_config(config)
        click.echo("Session cleared")
    else:
        click.echo("No active session")


@auth.command()
def status():
    """Check authentication status."""
    config = load_config()
    if "session" in config:
        session = config["session"]
        click.echo(f"Authenticated as: {session['did']}")
        click.echo(f"Token: {session['token'][:20]}...")
    else:
        click.echo("Not authenticated")


@cli.group()
def data():
    """Data operations."""
    pass


def get_session_from_config():
    """Get session from config or error."""
    config = load_config()
    if "session" not in config:
        click.echo("Not authenticated. Please run: willow-cli auth login")
        sys.exit(1)
    return config["session"]


@data.command()
@click.argument("dataset_id")
@click.argument("data", type=click.File("r"))
@click.pass_context
def store(ctx, dataset_id, data):
    """Store data in a dataset. Data should be JSON file or - for stdin."""
    async def _store():
        session = get_session_from_config()
        data_dict = json.load(data)
        
        async with WillowClient(ctx.obj["api_url"]) as client:
            # Restore session
            client.session = type("Session", (), session)()
            
            await client.data.store(dataset_id, data_dict)
            click.echo(f"Stored {len(data_dict)} items")
    
    asyncio.run(_store())


@data.command()
@click.argument("dataset_id")
@click.argument("key")
@click.pass_context
def get(ctx, dataset_id, key):
    """Get data from a dataset."""
    async def _get():
        session = get_session_from_config()
        
        async with WillowClient(ctx.obj["api_url"]) as client:
            # Restore session
            client.session = type("Session", (), session)()
            
            result = await client.data.get(dataset_id, key)
            click.echo(json.dumps(result, indent=2))
    
    asyncio.run(_get())


@data.command()
@click.argument("dataset_id")
@click.argument("key")
@click.argument("data", type=click.File("r"))
@click.pass_context
def update(ctx, dataset_id, key, data):
    """Update data in a dataset."""
    async def _update():
        session = get_session_from_config()
        data_dict = json.load(data)
        
        async with WillowClient(ctx.obj["api_url"]) as client:
            # Restore session
            client.session = type("Session", (), session)()
            
            await client.data.update(dataset_id, key, data_dict)
            click.echo(f"Updated {key}")
    
    asyncio.run(_update())


@data.command()
@click.argument("dataset_id")
@click.argument("key")
@click.pass_context
def delete(ctx, dataset_id, key):
    """Delete data from a dataset."""
    async def _delete():
        session = get_session_from_config()
        
        async with WillowClient(ctx.obj["api_url"]) as client:
            # Restore session
            client.session = type("Session", (), session)()
            
            await client.data.delete(dataset_id, key)
            click.echo(f"Deleted {key}")
    
    asyncio.run(_delete())


@cli.group()
def proof():
    """Proof operations."""
    pass


@proof.command()
@click.argument("dataset_id")
@click.argument("key")
@click.pass_context
def get(ctx, dataset_id, key):
    """Get Merkle proof for data."""
    async def _get_proof():
        async with WillowClient(ctx.obj["api_url"]) as client:
            result = await client.proof.get(dataset_id, key)
            click.echo(json.dumps(result, indent=2))
    
    asyncio.run(_get_proof())


def main():
    """Main entry point."""
    cli(obj={})


if __name__ == "__main__":
    main()