"""The CLI keeps the saved identity's algorithm and signs with it."""

import json

import pytest
from click.testing import CliRunner

from willow import cli, generate_did


@pytest.fixture
def config_file(tmp_path, monkeypatch):
    path = tmp_path / ".willow" / "config.json"
    monkeypatch.setattr(cli, "CONFIG_FILE", path)
    return path


def test_generate_saves_the_algorithm(config_file):
    result = CliRunner().invoke(cli.cli, ["did", "generate", "--algorithm", "secp256k1", "--save"])
    assert result.exit_code == 0, result.output
    assert json.loads(config_file.read_text())["identity"]["algorithm"] == "secp256k1"
    assert cli.get_identity_or_exit()[3] == "secp256k1"


def test_login_saves_the_algorithm_and_an_older_identity_is_ed25519(config_file):
    config_file.parent.mkdir()
    config_file.write_text(json.dumps({"identity": {
        "did": "did:willow:a", "private_key": "03" * 32, "public_key_id": "did:willow:a#key-1",
    }}))
    assert cli.get_identity_or_exit()[3] == "Ed25519"

    result = CliRunner().invoke(cli.cli, ["auth", "login", "--algorithm", "secp256k1"])
    assert result.exit_code == 0, result.output
    assert cli.get_identity_or_exit() == (
        "did:willow:a", "03" * 32, "did:willow:a#key-1", "secp256k1"
    )


@pytest.mark.parametrize("args", [["--did", "did:willow:b"], ["--key", "04" * 32], ["--did", "did:willow:b", "--key", "04" * 32]])
def test_login_with_another_did_or_key_does_not_inherit_the_saved_algorithm(config_file, args):
    CliRunner().invoke(cli.cli, ["did", "generate", "--algorithm", "secp256k1", "--save"])
    result = CliRunner().invoke(cli.cli, ["auth", "login", *args])
    assert result.exit_code == 0, result.output
    assert cli.get_identity_or_exit()[3] == "Ed25519"


def test_login_keeping_the_did_and_key_keeps_the_saved_algorithm(config_file):
    CliRunner().invoke(cli.cli, ["did", "generate", "--algorithm", "secp256k1", "--save"])
    did, key, _, _ = cli.get_identity_or_exit()
    for args in (["--key-id", f"{did}#key-2"], ["--did", did, "--key", key]):
        result = CliRunner().invoke(cli.cli, ["auth", "login", *args])
        assert result.exit_code == 0, result.output
        assert cli.get_identity_or_exit()[3] == "secp256k1"


def test_data_commands_sign_with_the_saved_algorithm(config_file, monkeypatch):
    CliRunner().invoke(cli.cli, ["did", "generate", "--algorithm", "secp256k1", "--save"])
    identities = []

    class Client:
        def __init__(self, api_url, consensus_rpc_url=None):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        def set_identity(self, *args):
            identities.append(args)

        class data:
            @staticmethod
            async def store(subgrove_id, data):
                return []

    monkeypatch.setattr(cli, "WillowClient", Client)
    result = CliRunner().invoke(cli.cli, ["data", "store", "sg", "-"], input='{"k": {}}')
    assert result.exit_code == 0, result.output
    assert identities[0][3] == "secp256k1"


def test_a_verified_get_says_what_to_set_and_sends_nothing_without_a_consensus_rpc(config_file, monkeypatch):
    CliRunner().invoke(cli.cli, ["did", "generate", "--save"])
    monkeypatch.delenv("WILLOW_CONSENSUS_RPC_URL", raising=False)
    result = CliRunner().invoke(cli.cli, ["--api-url", "http://127.0.0.1:9", "data", "get", "sg", "k"])
    assert result.exit_code == 1
    assert "no trusted header source" in result.output
    assert "--consensus-rpc-url" in result.output and "--unverified" in result.output


@pytest.mark.parametrize("args,env", [
    (["--consensus-rpc-url", "http://rpc.test:26657"], {}),
    ([], {"WILLOW_CONSENSUS_RPC_URL": "http://rpc.test:26657"}),
])
def test_a_verified_get_reads_headers_from_the_consensus_rpc_given(config_file, monkeypatch, args, env):
    CliRunner().invoke(cli.cli, ["did", "generate", "--save"])
    made = []

    class Client:
        def __init__(self, api_url, consensus_rpc_url=None):
            made.append((api_url, consensus_rpc_url))

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        def set_identity(self, *args):
            pass

        class data:
            @staticmethod
            async def get(subgrove_id, key):
                return {"v": 1}

    monkeypatch.setattr(cli, "WillowClient", Client)
    result = CliRunner().invoke(cli.cli, [*args, "data", "get", "sg", "k"], env=env)
    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {"v": 1}
    assert made == [("http://localhost:3031", "http://rpc.test:26657")]


@pytest.mark.parametrize("command,stdin", [
    (["did", "register", "-"], None),
    (["data", "store", "sg", "-"], '{"k": {}}'),
    (["data", "get", "sg", "k"], None),
    (["data", "update", "sg", "k", "-"], "{}"),
    (["data", "delete", "sg", "k"], None),
    (["proof", "get", "sg", "k"], None),
])
def test_every_command_builds_its_client_with_the_consensus_rpc_given(config_file, monkeypatch, command, stdin):
    CliRunner().invoke(cli.cli, ["did", "generate", "--save"])
    if command[:2] == ["did", "register"]:
        stdin = json.dumps(generate_did()["did_document"].model_dump(by_alias=True))
    made = []

    class Built(Exception):
        pass

    def client(api_url, consensus_rpc_url=None, **kwargs):
        made.append(consensus_rpc_url)
        raise Built()

    monkeypatch.setattr(cli, "WillowClient", client)
    result = CliRunner().invoke(cli.cli, ["--consensus-rpc-url", "http://rpc.test:26657", *command], input=stdin)
    assert isinstance(result.exception, Built), result.output
    assert made == ["http://rpc.test:26657"]
