"""
Willow Python SDK - Token and Validator Operations Example

This example demonstrates economic operations:
1. Query token information
2. Check balances
3. View fee schedules
4. Query validator information
5. View staking stats

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
        # Authenticate
        await client.register_did(did_info["did_document"])
        await client.authenticate(
            did=did_info["did"],
            private_key_hex=did_info["private_key"],
            public_key_id=did_info["public_key_id"]
        )

        # ============ TOKEN OPERATIONS ============

        # 1. Get Token Info
        print("\n1. Token Information")
        print("-" * 40)

        try:
            token_info = await client.token.get_info()
            print(f"Name: {token_info.name}")
            print(f"Symbol: {token_info.symbol}")
            print(f"Decimals: {token_info.decimals}")
            print(f"Max Supply: {token_info.max_supply}")
            print(f"Circulating Supply: {token_info.circulating_supply}")
        except WillowError as e:
            print(f"Error: {e}")

        # 2. Get Account Balance
        print("\n2. Account Balance")
        print("-" * 40)

        try:
            balance = await client.token.get_balance(did_info["did"])
            print(f"Available: {balance.available}")
            print(f"Locked: {balance.locked}")
            print(f"Total: {balance.total}")
        except WillowError as e:
            print(f"Error: {e}")

        # 3. Get App Balance
        print("\n3. App Balance")
        print("-" * 40)

        try:
            app_balance = await client.token.get_app_balance("demo-app")
            print(f"App balance: {app_balance}")
        except WillowError as e:
            print(f"Error: {e}")

        # 4. Get Fee Schedule
        print("\n4. Fee Schedule")
        print("-" * 40)

        try:
            fees = await client.token.get_fee_schedule()
            print(f"Base TX Cost: {fees.base_tx_cost} wei")
            print(f"Cost Per Byte: {fees.cost_per_byte} wei")
            print(f"Query Fee: {fees.query_fee} wei")
            print(f"Transfer Fee: {fees.transfer_fee_percentage} bps")
            print(f"Max TX Size: {fees.max_tx_size_bytes} bytes")
            print(f"Max Data Payload: {fees.max_data_payload_bytes} bytes")
        except WillowError as e:
            print(f"Error: {e}")

        # ============ VALIDATOR OPERATIONS ============

        # 5. List Validators
        print("\n5. List Validators")
        print("-" * 40)

        try:
            validators = await client.validators.list()
            print(f"Total validators: {len(validators)}")
            for v in validators[:5]:
                print(f"  - {v.address[:16]}... ({v.status})")
                print(f"    Stake: {v.stake}, Voting Power: {v.voting_power}")
        except WillowError as e:
            print(f"Error: {e}")

        # 6. Get Specific Validator
        print("\n6. Get Validator Details")
        print("-" * 40)

        try:
            validators = await client.validators.list()
            if validators:
                validator = await client.validators.get(validators[0].address)
                print(f"Address: {validator.address}")
                print(f"Status: {validator.status}")
                print(f"Stake: {validator.stake}")
                print(f"Voting Power: {validator.voting_power}")
        except WillowError as e:
            print(f"Error: {e}")

        # 7. Get Total Staked
        print("\n7. Total Staked")
        print("-" * 40)

        try:
            total_staked = await client.validators.get_total_staked()
            print(f"Total staked: {total_staked}")
        except WillowError as e:
            print(f"Error: {e}")

        # 8. Get Active Validator Count
        print("\n8. Active Validators")
        print("-" * 40)

        try:
            active_count = await client.validators.get_active_count()
            print(f"Active validators: {active_count}")
        except WillowError as e:
            print(f"Error: {e}")

    print("\n" + "=" * 50)
    print("Economic Model Summary:")
    print("- WILL token for storage fees and staking")
    print("- Pay-per-storage model (automatic deduction)")
    print("- Validators secure the network via PoS")
    print("- Indexers earn rewards for indexing work")


if __name__ == "__main__":
    asyncio.run(main())
