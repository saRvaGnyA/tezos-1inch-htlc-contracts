"""
IEscrowHub.py - Cross-Chain Escrow Hub Interface

Interface specification for the secure cross-chain escrow hub contract.
Defines all entrypoints, types, and events for cross-chain atomic swaps.
"""

import smartpy as sp


@sp.module
def IEscrowHub():
    # =========================================================================
    # BASIC TYPE DEFINITIONS
    # =========================================================================

    t_unit: type = sp.unit
    t_nat: type = sp.nat
    t_bool: type = sp.bool
    t_address: type = sp.address
    t_bytes: type = sp.bytes
    t_timestamp: type = sp.timestamp
    t_mutez: type = sp.mutez

    # ================================================================
    # ====================== COMPLEX TYPE DEFINITIONS ================
    # ================================================================

    # Timelock structure used in escrows
    timelock_type: type = sp.record(
        withdrawal=t_timestamp,  # When taker can withdraw
        public_withdrawal=t_timestamp,  # When anyone can withdraw
        cancellation=t_timestamp,  # When taker can cancel
        public_cancellation=t_timestamp,  # When anyone can cancel
    )

    # Escrow status variants
    escrow_status_type: type = sp.variant(
        active=t_unit,  # Escrow is active
        withdrawn=t_unit,  # Successfully withdrawn
        cancelled=t_unit,  # Cancelled and refunded
    )

    # Cross-chain escrow data structure
    escrow_record_type: type = sp.record(
        # Hash and Identity
        hashlock=t_bytes,  # SHA-256 hash of secret
        maker1=t_address,  # Native tz1 format (Tezos)
        taker1=t_address,  # Native tz1 format (Tezos)
        maker_evm_bytes=t_bytes,  # 20-byte EVM format for cross-chain
        taker_evm_bytes=t_bytes,  # 20-byte EVM format for cross-chain
        # Token and Amount
        token_contract=t_address,  # FA2/FA1.2 contract address
        token_id=t_nat,  # Token ID (0 for FA1.2)
        amount=t_nat,  # Token amount to swap
        safety_deposit=t_mutez,  # XTZ safety deposit
        is_fa2=t_bool,  # True for FA2, False for FA1.2
        # Timing
        timelocks=timelock_type,
        # State
        status=escrow_status_type,
    )

    # Escrow creation parameters
    create_escrow_params_type: type = sp.record(
        maker=t_address,  # Native tzl format
        taker=t_address,  # Native tzl format
        maker_evm_bytes=t_bytes,  # 20-byte EVM format
        taker_evm_bytes=t_bytes,  # 20-byte EVM format
        hashlock=t_bytes,  # SHA-256 hash of secret
        token_contract=t_address,  # FA2/FA1.2 contract
        token_id=t_nat,  # Token ID (0 for FA1.2)
        amount=t_nat,  # Token amount
        safety_deposit=t_mutez,  # XTZ safety deposit
        timelocks=timelock_type,
    )

    # Withdraw parameters
    withdraw_params_type: type = sp.record(escrow_key=t_bytes, secret=t_bytes)

    # Cancel parameters
    cancel_params_type: type = sp.record(escrow_key=t_bytes)

    # Rescue parameters
    rescue_params_type: type = sp.record(
        token_contract=t_address,
        token_id=t_nat,
        amount=t_nat,
        recipient=t_address,
        escrow_key=t_bytes,
    )

    # =========================================================================
    # EVENT TYPES
    # =========================================================================

    # Cross-chain escrow created event
    escrow_created_event_type: type = sp.record(
        escrow_key=t_bytes,
        hub_address=t_address,
        maker_tezos=t_address,
        maker_evm=t_bytes,
        taker_tezos=t_address,
        taker_evm=t_bytes,
        hashlock=t_bytes,
        token_contract=t_address,
        token_id=t_nat,
        amount=t_nat,
        safety_deposit=t_mutez,
        withdrawal_time=t_timestamp,
        cancellation_time=t_timestamp,
    )

    # Cross-chain withdrawal event
    withdrawal_event_type: type = sp.record(
        escrow_key=t_bytes,
        secret_hash=t_bytes,
        withdrawer=t_address,
        taker_tezos=t_address,
        taker_evm=t_bytes,
        amount=t_nat,
        safety_deposit=t_mutez,
        is_public_withdrawal=t_bool,
    )

    # Cross-chain cancellation event
    cancellation_event_type: type = sp.record(
        escrow_key=t_bytes,
        canceller=t_address,
        maker_tezos=t_address,
        maker_evm=t_bytes,
        amount=t_nat,
        safety_deposit=t_mutez,
        is_public_cancellation=t_bool,
    )

    # Emergency unlock event
    emergency_unlock_event_type: type = sp.record(escrow_key=t_bytes, admin=t_address)

    # Tokens rescued event
    tokens_rescued_event_type: type = sp.record(
        escrow_key=t_bytes,
        token_contract=t_address,
        token_id=t_nat,
        amount=t_nat,
        recipient=t_address,
    )

    # Cross-chain escrow data structure
    escrow_record_type: type = sp.record(
        hash=t_bytes,  # SHA-256 hash of secret
        maker=t_address,  # Native tzl format (Tezos)
        taker=t_address,  # Native tzl format (Tezos)
        maker_evm_bytes=t_bytes,  # 20-byte EVM format for cross-chain
        taker_evm_bytes=t_bytes,  # 20-byte EVM format for cross-chain
    )

    # =========================================================================
    # INTERFACE SPECIFICATION
    # =========================================================================

    class IEscrowHubInterface(sp.Contract):
        """
        Interface specification for Cross-Chain Escrow Hub

        This interface defines all required entrypoints and their signatures
        for a compliant cross-chain escrow hub implementation.
        """

        # =========================================================================
        # MAIN ENTRYPOINTS
        # =========================================================================

        @sp.entrypoint
        def create_escrow(self, params):
            """
            Create new cross-chain escrow entry

            Args:
                params: create_escrow_params_type - Escrow parameters

            Requires:
                - sp.amount == params.safety_deposit
                - Valid cross-chain addresses
                - Proper timelock sequence

            Emits:
                - CrossChainEscrowCreated event

            Effects:
                - Creates new escrow in hub storage
                - Transfers tokens to hub
                - Receives XTZ safety deposit
            """
            sp.cast(params, create_escrow_params_type)
            # Implementation provided by concrete contract
            pass

        @sp.entrypoint
        def withdraw(self, params):
            """
            Withdraw tokens from escrow using secret

            Args:
                params: withdraw_params_type - Escrow key and secret

            Requires:
                - Valid secret matching hashlock
                - Current time within withdrawal window
                - Caller is taker or in public period
                - Escrow status is active

            Emits:
                - CrossChainWithdrawal event

            Effects:
                - Transfers tokens to taker
                - Transfers safety deposit to caller
                - Marks escrow as withdrawn
            """
            sp.cast(params, withdraw_params_type)
            # Implementation provided by concrete contract
            pass

        @sp.entrypoint
        def cancel(self, params):
            """
            Cancel escrow and return funds to maker

            Args:
                params: cancel_params_type - Escrow key

            Requires:
                - Current time within cancellation window
                - Caller is taker or in public period
                - Escrow status is active

            Emits:
                - CrossChainCancellation event

            Effects:
                - Returns tokens to maker
                - Transfers safety deposit to caller
                - Marks escrow as cancelled
            """
            sp.cast(params, cancel_params_type)
            # Implementation provided by concrete contract
            pass

        # =========================================================================
        # VIEW ENTRYPOINTS
        # =========================================================================

        @sp.entrypoint
        def get_escrow(self, escrow_key):
            """
            Get escrow data by key

            Args:
                escrow_key: bytes - Escrow identifier

            Returns:
                escrow_record_type - Complete escrow data

            Throws:
                ESCROW_NOT_FOUND - If escrow doesn't exist
            """
            sp.cast(escrow_key, t_bytes)
            # Implementation provided by concrete contract
            pass

        @sp.entrypoint
        def get_escrow_status(self, escrow_key):
            """
            Get escrow status only

            Args:
                escrow_key: bytes - Escrow identifier

            Returns:
                variant - Current escrow status (active/withdrawn/cancelled)

            Throws:
                ESCROW_NOT_FOUND - If escrow doesn't exist
            """
            sp.cast(escrow_key, t_bytes)
            # Implementation provided by concrete contract
            pass

        @sp.entrypoint
        def is_escrow_locked(self, escrow_key):
            """
            Check if escrow is currently locked

            Args:
                escrow_key: bytes - Escrow identifier

            Returns:
                bool - True if escrow is locked for re-entrancy protection
            """
            sp.cast(escrow_key, t_bytes)
            # Implementation provided by concrete contract
            pass

        # =========================================================================
        # ADMIN ENTRYPOINTS
        # =========================================================================

        @sp.entrypoint
        def emergency_unlock_escrow(self, escrow_key):
            """
            Emergency unlock specific escrow (admin only)

            Args:
                escrow_key: bytes - Escrow to unlock

            Requires:
                - Caller is admin

            Emits:
                - EmergencyUnlock event

            Effects:
                - Clears per-escrow lock
            """
            sp.cast(escrow_key, t_bytes)
            # Implementation provided by concrete contract
            pass

        @sp.entrypoint
        def rescue_stuck_tokens(self, params):
            """
            Rescue tokens stuck in contract after rescue delay (admin only)

            Args:
                params: rescue_params_type - Rescue parameters

            Requires:
                - Caller is admin
                - Rescue delay has expired
                - Escrow is not active

            Emits:
                - TokensRescued event

            Effects:
                - Transfers tokens to recipient
            """
            sp.cast(params, rescue_params_type)
            # Implementation provided by concrete contract
            pass


# =============================================================================
# DOCUMENTATION
# =============================================================================

"""
CROSS-CHAIN ESCROW HUB INTERFACE SPECIFICATION

This interface defines the complete API for a secure cross-chain escrow hub
that enables atomic swaps between EVM chains and Tezos.

Key Features:
- Hub-based architecture (single contract, big_map storage)
- Per-escrow locking (prevents DoS attacks)
- Cross-chain address compatibility (tzl ↔ bytes20)
- Native XTZ safety deposits
- Comprehensive security validations

Usage Pattern:
1. Relayer calculates cross-chain timelocks
2. Resolver calls create_escrow() with safety deposit
3. Hub validates parameters and stores escrow data
4. Tokens transferred to hub, safety deposit held
5. After finality, secret revealed for withdrawals
6. Either withdraw() or cancel() completes the swap

Security Guarantees:
- Atomic: Either both chains succeed or both fail
- Non-custodial: No central authority controls funds
- Time-bounded: Automatic refunds after timeouts
- Incentive-aligned: Safety deposits ensure cooperation
- Re-entrancy safe: Per-escrow locking prevents attacks

Integration:
- Implement IEscrowHubInterface for compliance
- Use provided type definitions for parameters
- Emit events with standardized formats
- Follow error code conventions
- Respect timing constraints

For complete implementation example, see EscrowHub.py
"""

if "main" in __name__:
    print("IEscrowHub Interface Specification")
    print("See EscrowHub.py for concrete implementation")
