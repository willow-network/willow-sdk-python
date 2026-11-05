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
from .errors import ProofVerificationError, WillowError
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


def get_identity_or_exit() -> Tuple[str, str, str, str]:
    """Return (did, private_key, public_key_id, algorithm) from config, or
    exit. An identity saved without an algorithm is Ed25519."""
    config = load_config()
    identity = config.get("identity")
    if not identity:
        click.echo("Not authenticated. Run: willow-cli auth login")
        sys.exit(1)
    return (
        identity["did"],
        identity["private_key"],
        identity["public_key_id"],
        identity.get("algorithm", "Ed25519"),
    )


@click.group()
@click.option("--api-url", default="http://localhost:3031", help="Willow API URL")
@click.option(
    "--consensus-rpc-url",
    envvar="WILLOW_CONSENSUS_RPC_URL",
    default=None,
    help="CometBFT RPC URL of a node you trust (typically port 26657): verified reads check "
         "their proofs against its headers. Also read from WILLOW_CONSENSUS_RPC_URL.",
)
@click.pass_context
def cli(ctx, api_url, consensus_rpc_url):
    """Willow CLI - Interact with Willow from the command line."""
    ctx.ensure_object(dict)
    ctx.obj["api_url"] = api_url
    ctx.obj["consensus_rpc_url"] = consensus_rpc_url


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
            "algorithm": output["algorithm"],
        }
        save_config(config)
        click.echo("Identity saved to config file")

    click.echo(json.dumps(output, indent=2))


@did.command()
@click.argument("did_file", type=click.File("r"))
@click.pass_context
def register(ctx, did_file):
    """Register a DID document (a RegisterDid transaction).

    Signed with the saved identity's key, which must be the document's DID,
    in the algorithm the document's key type names. Pre-fund that DID with
    the registration fee first.
    """

    async def _register():
        did_val, key_val, key_id_val, algorithm = get_identity_or_exit()
        did_doc_data = json.load(did_file)
        did_doc = DidDocument(**did_doc_data)

        async with WillowClient(ctx.obj["api_url"]) as client:
            client.set_identity(did_val, key_val, key_id_val, algorithm)
            result = await client.register_did(did_doc)
            click.echo(f"DID registration submitted: {did_doc.id} (tx {result.get('tx_hash')})")

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
@click.option(
    "--algorithm",
    "algorithm_arg",
    type=click.Choice(["Ed25519", "secp256k1"]),
    help="The key's algorithm (default: the saved identity's when the DID and key are the saved ones, else Ed25519)",
)
def login(did_arg, key_arg, key_id_arg, algorithm_arg):
    """Save identity (DID + key + key-id + algorithm) to ~/.willow/config.json."""
    config = load_config()
    existing = config.get("identity") or {}

    did_val = did_arg or existing.get("did")
    key_val = key_arg or existing.get("private_key")
    key_id_val = key_id_arg or existing.get("public_key_id")
    # The saved algorithm belongs to the saved key: another DID or key
    # doesn't inherit it.
    same_identity = did_val == existing.get("did") and key_val == existing.get("private_key")
    algorithm_val = algorithm_arg or (existing.get("algorithm", "Ed25519") if same_identity else "Ed25519")

    if not (did_val and key_val and key_id_val):
        click.echo("Need --did, --key, and --key-id (or run `willow-cli did generate --save` first).")
        sys.exit(1)

    config["identity"] = {
        "did": did_val,
        "private_key": key_val,
        "public_key_id": key_id_val,
        "algorithm": algorithm_val,
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
    """Store data in a subgrove, one StoreData transaction per key.

    DATA_FILE is a JSON object of key -> JSON object (or '-' for stdin).
    """

    async def _store():
        did_val, key_val, key_id_val, algorithm = get_identity_or_exit()
        data_dict = json.load(data_file)

        async with WillowClient(ctx.obj["api_url"]) as client:
            client.set_identity(did_val, key_val, key_id_val, algorithm)
            await client.data.store(subgrove_id, data_dict)
            click.echo(f"Stored {len(data_dict)} items in {subgrove_id}")

    asyncio.run(_store())


@data.command()
@click.argument("subgrove_id")
@click.argument("key")
@click.option("--unverified", is_flag=True, help="Print the value the API serves, without verifying it.")
@click.pass_context
def get(ctx, subgrove_id, key, unverified):
    """Get a single item from a subgrove, verified against its proof and the
    headers of --consensus-rpc-url (or --unverified)."""

    async def _get():
        did_val, key_val, key_id_val, algorithm = get_identity_or_exit()
        rpc_url = ctx.obj.get("consensus_rpc_url")

        async with WillowClient(ctx.obj["api_url"], consensus_rpc_url=rpc_url) as client:
            client.set_identity(did_val, key_val, key_id_val, algorithm)
            try:
                if unverified:
                    result = await client.data.get_unverified(subgrove_id, key)
                else:
                    result = await client.data.get(subgrove_id, key)
            except ProofVerificationError as e:
                if rpc_url:
                    hint = "Use --unverified to print the value unverified."
                else:
                    hint = (
                        "Pass --consensus-rpc-url <CometBFT RPC of a node you trust> (or set "
                        "WILLOW_CONSENSUS_RPC_URL) to verify it, or --unverified to print the value "
                        "unverified."
                    )
                click.echo(f"Not verified: {e}. {hint}", err=True)
                sys.exit(1)
            click.echo(json.dumps(result, indent=2))

    asyncio.run(_get())


@data.command()
@click.argument("subgrove_id")
@click.argument("key")
@click.argument("data_file", type=click.File("r"))
@click.pass_context
def update(ctx, subgrove_id, key, data_file):
    """Update an item in a subgrove (not supported: the SDK builds no UpdateData)."""

    async def _update():
        did_val, key_val, key_id_val, algorithm = get_identity_or_exit()
        data_dict = json.load(data_file)

        async with WillowClient(ctx.obj["api_url"]) as client:
            client.set_identity(did_val, key_val, key_id_val, algorithm)
            try:
                await client.data.update(subgrove_id, key, data_dict)
            except WillowError as e:
                click.echo(str(e), err=True)
                sys.exit(1)
            click.echo(f"Updated {key} in {subgrove_id}")

    asyncio.run(_update())


@data.command()
@click.argument("subgrove_id")
@click.argument("key")
@click.pass_context
def delete(ctx, subgrove_id, key):
    """Delete an item from a subgrove (not supported: the SDK builds no DeleteData)."""

    async def _delete():
        did_val, key_val, key_id_val, algorithm = get_identity_or_exit()

        async with WillowClient(ctx.obj["api_url"]) as client:
            client.set_identity(did_val, key_val, key_id_val, algorithm)
            try:
                await client.data.delete(subgrove_id, key)
            except WillowError as e:
                click.echo(str(e), err=True)
                sys.exit(1)
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
