"""
ERC-8004 (Trustless Agents) integration for Willow.

Provides helpers to link Ethereum addresses to Willow DIDs and interact
with on-chain ERC-8004 agent registrations.
"""

from dataclasses import dataclass, field
from typing import List, Optional

import aiohttp


@dataclass
class AgentService:
    name: str
    endpoint: str


@dataclass
class AgentChainRegistration:
    chain_id: int
    registry: str
    agent_id: int


@dataclass
class AgentReputationSummary:
    checkpoint_success_rate: float
    verification_accuracy: float
    active_days: int
    last_updated: int


@dataclass
class AgentRegistrationJson:
    type: str
    name: str
    description: str
    services: List[AgentService]
    x402_support: bool
    active: bool
    registrations: List[AgentChainRegistration]
    supported_trust: List[str]
    reputation: Optional[AgentReputationSummary] = None


@dataclass
class ReputationAttestation:
    did: str
    metrics: dict
    proof: str
    block_height: int
    last_updated: int


@dataclass
class ReputationHistoryEvent:
    event_type: str
    block_height: int
    timestamp: int
    reference: Optional[str] = None


@dataclass
class ReputationHistoryResponse:
    did: str
    events: List[ReputationHistoryEvent]
    total_events: int


@dataclass
class Erc8004Registration:
    chain_id: int
    registry_address: List[int]
    agent_id: int
    agent_uri: str
    registered_at: int


@dataclass
class LinkEthAddressTx:
    did: str
    eth_address: str
    public_key_id: str
    signature: Optional[str] = None
    nonce: Optional[int] = None


@dataclass
class RegisterErc8004AgentTx:
    did: str
    chain_id: int
    registry_address: str
    agent_id: int
    agent_uri: str
    signature: Optional[str] = None
    public_key_id: Optional[str] = None
    nonce: Optional[int] = None


@dataclass
class Erc8004ValidationRecord:
    request_hash: str
    subgrove_id: str
    block_range: List[int]
    state_root: str
    response: int
    status: str
    tee_verified: bool
    submitted_at_block: int
    tag: str
    tee_type: Optional[str] = None
    challenge_deadline: Optional[int] = None


@dataclass
class ValidationStatusBreakdown:
    trusted: int
    pending_challenge: int
    tee_attested: int
    disputed: int
    invalidated: int


@dataclass
class DisputeStats:
    disputes_won_as_defendant: int
    disputes_lost_as_defendant: int
    disputes_won_as_challenger: int
    disputes_lost_as_challenger: int


@dataclass
class Erc8004ValidationStatusResponse:
    did: str
    validations: List[Erc8004ValidationRecord]
    total: int


@dataclass
class Erc8004ValidationSummary:
    did: str
    count: int
    average_response: float
    status_breakdown: ValidationStatusBreakdown
    dispute_stats: DisputeStats


@dataclass
class Erc8004AgentListItem:
    did: str
    agent_uri: str
    chain_id: int
    agent_id: int
    validation_count: int
    registered_at: int
    eth_address: Optional[str] = None


@dataclass
class Erc8004AgentListResponse:
    agents: List[Erc8004AgentListItem]
    total: int
    offset: int
    limit: int


class Erc8004Client:
    """Client for ERC-8004 agent identity operations."""

    def __init__(self, api_url: str):
        self._api_url = api_url.rstrip("/")

    async def list_agents(
        self,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> Erc8004AgentListResponse:
        """List/search ERC-8004 registered agents with optional filters."""
        params = {}
        if limit is not None:
            params["limit"] = str(limit)
        if offset is not None:
            params["offset"] = str(offset)
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self._api_url}/agents", params=params
            ) as resp:
                body = await resp.json()
                if body.get("success") is False:
                    raise Exception(body.get("error", "Unknown error"))
                data = body["data"]
                return Erc8004AgentListResponse(
                    agents=[
                        Erc8004AgentListItem(
                            did=a["did"],
                            eth_address=a.get("eth_address"),
                            agent_uri=a["agent_uri"],
                            chain_id=a["chain_id"],
                            agent_id=a["agent_id"],
                            validation_count=a["validation_count"],
                            registered_at=a["registered_at"],
                        )
                        for a in data["agents"]
                    ],
                    total=data["total"],
                    offset=data["offset"],
                    limit=data["limit"],
                )

    async def get_agent_registration(self, did: str) -> AgentRegistrationJson:
        """Fetch the ERC-8004 registration JSON for an agent DID."""
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self._api_url}/agent/{did}/registration.json"
            ) as resp:
                body = await resp.json()
                if body.get("success") is False:
                    raise Exception(body.get("error", "Unknown error"))
                data = body["data"]
                return AgentRegistrationJson(
                    type=data["type"],
                    name=data["name"],
                    description=data["description"],
                    services=[AgentService(**s) for s in data["services"]],
                    x402_support=data["x402_support"],
                    active=data["active"],
                    registrations=[
                        AgentChainRegistration(**r) for r in data["registrations"]
                    ],
                    supported_trust=data["supported_trust"],
                )

    async def get_eth_address(self, did: str) -> Optional[str]:
        """Get the ETH address linked to a DID."""
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self._api_url}/did/{did}/eth-address"
            ) as resp:
                if resp.status == 404:
                    return None
                body = await resp.json()
                if body.get("success") is False:
                    raise Exception(body.get("error", "Unknown error"))
                return body.get("data", {}).get("eth_address")

    async def get_did_for_eth(self, eth_address: str) -> Optional[str]:
        """Get the DID linked to an ETH address."""
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self._api_url}/eth-address/{eth_address}/did"
            ) as resp:
                if resp.status == 404:
                    return None
                body = await resp.json()
                if body.get("success") is False:
                    raise Exception(body.get("error", "Unknown error"))
                return body.get("data", {}).get("did")

    async def get_erc8004_details(self, did: str) -> Optional[Erc8004Registration]:
        """Get stored ERC-8004 registration details for a DID."""
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self._api_url}/did/{did}/erc8004"
            ) as resp:
                if resp.status == 404:
                    return None
                body = await resp.json()
                if body.get("success") is False:
                    raise Exception(body.get("error", "Unknown error"))
                data = body.get("data")
                if data is None:
                    return None
                return Erc8004Registration(
                    chain_id=data["chain_id"],
                    registry_address=data["registry_address"],
                    agent_id=data["agent_id"],
                    agent_uri=data["agent_uri"],
                    registered_at=data["registered_at"],
                )

    async def get_reputation_attestation(self, did: str) -> ReputationAttestation:
        """Fetch reputation attestation with GroveDB Merkle proof for a DID."""
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self._api_url}/agent/{did}/reputation-attestation"
            ) as resp:
                body = await resp.json()
                if body.get("success") is False:
                    raise Exception(body.get("error", "Unknown error"))
                data = body["data"]
                return ReputationAttestation(
                    did=data["did"],
                    metrics=data["metrics"],
                    proof=data["proof"],
                    block_height=data["block_height"],
                    last_updated=data["last_updated"],
                )

    async def get_reputation_history(
        self, did: str, limit: Optional[int] = None
    ) -> ReputationHistoryResponse:
        """Fetch ERC-8004 formatted reputation history for a DID."""
        params = {}
        if limit is not None:
            params["limit"] = str(limit)
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self._api_url}/agent/{did}/reputation-history",
                params=params,
            ) as resp:
                body = await resp.json()
                if body.get("success") is False:
                    raise Exception(body.get("error", "Unknown error"))
                data = body["data"]
                return ReputationHistoryResponse(
                    did=data["did"],
                    events=[
                        ReputationHistoryEvent(
                            event_type=e["event_type"],
                            block_height=e["block_height"],
                            timestamp=e["timestamp"],
                            reference=e.get("reference"),
                        )
                        for e in data["events"]
                    ],
                    total_events=data["total_events"],
                )

    async def get_validation_status(
        self, did: str, limit: Optional[int] = None, subgrove_id: Optional[str] = None
    ) -> Erc8004ValidationStatusResponse:
        """Fetch ERC-8004 validation status (checkpoint validations) for a DID."""
        params = {}
        if limit is not None:
            params["limit"] = str(limit)
        if subgrove_id is not None:
            params["subgrove_id"] = subgrove_id
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self._api_url}/agent/{did}/validation-status",
                params=params,
            ) as resp:
                body = await resp.json()
                if body.get("success") is False:
                    raise Exception(body.get("error", "Unknown error"))
                data = body["data"]
                return Erc8004ValidationStatusResponse(
                    did=data["did"],
                    validations=[
                        Erc8004ValidationRecord(
                            request_hash=v["request_hash"],
                            subgrove_id=v["subgrove_id"],
                            block_range=v["block_range"],
                            state_root=v["state_root"],
                            response=v["response"],
                            status=v["status"],
                            tee_verified=v["tee_verified"],
                            tee_type=v.get("tee_type"),
                            submitted_at_block=v["submitted_at_block"],
                            challenge_deadline=v.get("challenge_deadline"),
                            tag=v["tag"],
                        )
                        for v in data["validations"]
                    ],
                    total=data["total"],
                )

    async def get_validation_summary(
        self, did: str, subgrove_id: Optional[str] = None
    ) -> Erc8004ValidationSummary:
        """Fetch aggregated ERC-8004 validation summary for a DID."""
        params = {}
        if subgrove_id is not None:
            params["subgrove_id"] = subgrove_id
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self._api_url}/agent/{did}/validation-summary",
                params=params,
            ) as resp:
                body = await resp.json()
                if body.get("success") is False:
                    raise Exception(body.get("error", "Unknown error"))
                data = body["data"]
                sb = data["status_breakdown"]
                ds = data["dispute_stats"]
                return Erc8004ValidationSummary(
                    did=data["did"],
                    count=data["count"],
                    average_response=data["average_response"],
                    status_breakdown=ValidationStatusBreakdown(
                        trusted=sb["trusted"],
                        pending_challenge=sb["pending_challenge"],
                        tee_attested=sb["tee_attested"],
                        disputed=sb["disputed"],
                        invalidated=sb["invalidated"],
                    ),
                    dispute_stats=DisputeStats(
                        disputes_won_as_defendant=ds["disputes_won_as_defendant"],
                        disputes_lost_as_defendant=ds["disputes_lost_as_defendant"],
                        disputes_won_as_challenger=ds["disputes_won_as_challenger"],
                        disputes_lost_as_challenger=ds["disputes_lost_as_challenger"],
                    ),
                )
