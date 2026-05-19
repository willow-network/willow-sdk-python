"""
Willow Python SDK - Token and Validator Operations Example

Read-only economic operations:
1. Query token info
2. Check DID balance
3. Check subgrove balance
4. View fee schedule
5. List validators
6. Get a specific validator
7. Get total staked
8. Get active validator count

Note: transfers and stakes are write operations that go through the
ConsensusClient (consensus.client.transfer / stake), not these read hooks.

Prerequisites:
- pip install willow-sdk
- Run a local Willow node
"""

import asyncio
from willow import (
    WillowClient,
    generate_did,
    WillowError,
)


async def main():
    print("Willow Token & Validator Demo")
    print("=" * 50)

    did_info = generate_did()

    async with WillowClient("http://localhost:3031") as client:
        # Auth
        await client.register_did(did_info["did_document"])
        client.set_identity(
            did_info["did"],
            did_info["private_key"],
            did_info["public_key_id"],
        )

        # 1. Token info
        print("\n1. Token Information")
        print("-" * 40)
        try:
            token_info = await client.token.get_info()
            print(f"Name: {token_info.name}")
            print(f"Symbol: {token_info.symbol}")
            print(f"Decimals: {token_info.decimals}")
            print(f"Genesis supply: {token_info.genesis_supply}")
            print(f"Minted supply: {token_info.minted_supply}")
            print(f"Max supply: {token_info.max_supply}")
            print(f"Circulating supply: {token_info.circulating_supply}")
        except WillowError as e:
            print(f"Error: {e}")

        # 2. Account balance
        print("\n2. Account Balance")
        print("-" * 40)
        try:
            balance = await client.token.get_balance(did_info["did"])
            print(f"Account: {balance.account}")
            print(f"Balance: {balance.balance} WILL")
            print(f"Staked:  {balance.staked} WILL")
            print(f"Unbonding: {balance.unbonding} WILL")
        except WillowError as e:
            print(f"Error: {e}")

        # 3. Subgrove balance
        print("\n3. Subgrove Balance")
        print("-" * 40)
        try:
            sg_balance = await client.token.get_subgrove_balance("demo-subgrove")
            print(f"Subgrove balance: {sg_balance.balance} WILL")
        except WillowError as e:
            print(f"Error: {e}")

        # 4. Fee schedule
        print("\n4. Fee Schedule")
        print("-" * 40)
        try:
            fees = await client.token.get_fee_schedule()
            print(f"DID registration:      {fees.did_registration} WILL")
            print(f"Subgrove registration: {fees.subgrove_registration} WILL")
            print(f"Base TX cost:          {fees.base_tx_cost} WILL")
            print(f"Cost per byte:         {fees.cost_per_byte} WILL")
            print(f"Query fee:             {fees.query_fee} WILL")
            print(f"Transfer fee (bps):    {fees.transfer_fee_percentage}")
            print(f"Max TX size:           {fees.max_tx_size_bytes} bytes")
            print(f"Max data payload:      {fees.max_data_payload_bytes} bytes")
        except WillowError as e:
            print(f"Error: {e}")

        # 5. List validators
        print("\n5. List Validators")
        print("-" * 40)
        try:
            validators = await client.validators.list()
            print(f"Total validators: {len(validators)}")
            for v in validators[:5]:
                name = v.name or "(no name)"
                print(f"  - {v.validator_did[:24]}... ({v.status}): {name}")
                print(f"    stake={v.stake_amount}, voting_power={v.voting_power}")
        except WillowError as e:
            print(f"Error: {e}")

        # 6. Get a specific validator
        print("\n6. Get Validator Details")
        print("-" * 40)
        try:
            validators = await client.validators.list()
            if validators:
                v = await client.validators.get(validators[0].validator_did)
                print(f"DID: {v.validator_did}")
                print(f"Status: {v.status}")
                print(f"Stake amount: {v.stake_amount}")
                print(f"Voting power: {v.voting_power}")
                if v.consensus_pubkey:
                    print(f"Consensus pubkey: {v.consensus_pubkey[:24]}...")
        except WillowError as e:
            print(f"Error: {e}")

        # 7. Total staked
        print("\n7. Total Staked")
        print("-" * 40)
        try:
            total = await client.validators.get_total_staked()
            print(f"Total staked: {total}")
        except WillowError as e:
            print(f"Error: {e}")

        # 8. Active count
        print("\n8. Active Validators")
        print("-" * 40)
        try:
            active = await client.validators.get_active_count()
            print(f"Active validators: {active}")
        except WillowError as e:
            print(f"Error: {e}")

    print("\n" + "=" * 50)
    print("Economic Model Summary:")
    print("- WILL token for storage fees and staking")
    print("- Pay-per-storage model (automatic deduction)")
    print("- Validators secure the network via Proof of Stake")
    print("- Indexers earn rewards for indexing work")


if __name__ == "__main__":
    asyncio.run(main())
