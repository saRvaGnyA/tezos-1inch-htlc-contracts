"""
TimelockLib.py - Cross-Chain Timelock Management Library

Manages timelocks for cross-chain atomic swaps, ensuring proper sequencing
and gas-adjusted timing across different blockchain networks.

Key features:
- Multi-stage timelock validation
- Cross-chain timing coordination
- Gas-adjusted timelock calculations
- Compact timelock storage
"""

import smartpy as sp


@sp.module
def TimelockLib():
    # =========================================================================
    # BASIC TYPE DEFINITIONS
    # =========================================================================

    t_bool: type = sp.bool
    t_bytes: type = sp.bytes
    t_timestamp: type = sp.timestamp
    t_nat: type = sp.nat

    # ================================================================
    # ====================== COMPLEX TYPE DEFINITIONS ================
    # ================================================================

    # Timelock configuration structure
    timelock_config_type: type = sp.record(
        # Source chain timelocks (where maker's funds are locked)
        src_withdrawal=t_timestamp,  # When resolver can withdraw on source
        src_public_withdrawal=t_timestamp,  # When anyone can withdraw on source
        src_cancellation=t_timestamp,  # When maker can cancel on source
        src_public_cancellation=t_timestamp,  # When anyone can cancel on source
        # Destination chain timelocks (where resolver's funds are locked)
        dst_withdrawal=t_timestamp,  # When taker can withdraw on destination
        dst_public_withdrawal=t_timestamp,  # When anyone can withdraw on destination
        dst_cancellation=t_timestamp,  # When resolver can cancel on destination
        dst_public_cancellation=t_timestamp,  # When anyone can cancel on destination
        # Configuration
        coordination_buffer=t_nat,  # Buffer time between chains (seconds)
        gas_adjustment_factor=t_nat,  # Gas price impact factor
    )

    # Compact timelock representation for storage efficiency
    compact_timelock_type: type = sp.record(
        base_time=t_timestamp,  # Base timestamp
        withdrawal_offset=t_nat,  # Seconds from base to withdrawal
        public_withdrawal_offset=t_nat,  # Seconds from base to public withdrawal
        cancellation_offset=t_nat,  # Seconds from base to cancellation
        public_cancellation_offset=t_nat,  # Seconds from base to public cancellation
        is_source_chain=t_bool,  # Whether this is for source chain
    )

    class TimelockLibContract(sp.Contract):
        """
        Cross-Chain Timelock Management Library
        """

        def __init__(self, admin):
            """Initialize Timelock Library"""
            self.data = sp.record(
                # Configuration
                admin=admin,
                # Standard coordination buffer (10 minutes)
                default_coordination_buffer=sp.nat(600),
                # Active timelock configurations: order_hash -> timelock_config
                active_timelocks=sp.cast(
                    sp.big_map(),
                    sp.big_map[
                        t_bytes,
                        timelock_config_type,
                    ],
                ),
                # Compact storage: order_hash -> compact_timelock
                compact_timelocks=sp.cast(
                    sp.big_map(),
                    sp.big_map[
                        t_bytes,
                        compact_timelock_type,
                    ],
                ),
                # Gas price tracking
                current_gas_price=sp.nat(1000),  # Base gas price
                # Statistics
                total_timelock_configs=sp.nat(0),
            )

        # ================================================================
        # CORE TIMELOCK FUNCTIONS
        # ================================================================

        @sp.entrypoint
        def calculate_cross_chain_timelocks(self, params):
            """
            Calculate coordinated timelocks for both chains

            Ensures proper sequencing: dst_withdrawal < src_cancellation for atomicity.
            """
            sp.cast(
                params,
                sp.record(
                    order_hash=sp.bytes,
                    start_time=t_timestamp,
                    withdrawal_delay=t_nat,  # Delay before withdrawal allowed
                    cancellation_delay=t_nat,  # Delay before cancellation allowed
                    public_delay_additional=t_nat,  # Additional delay for public actions
                    gas_adjustment_factor=t_nat,  # Gas price impact (0-10000 basis points)
                ),
            )

            # Use centralized coordination buffer
            coordination_buffer = self.data.default_coordination_buffer

            # FIXED: Properly use cancellation_delay parameters and validate sequence
            assert (
                params.withdrawal_delay < params.cancellation_delay
            ), "CANCELLATION_BEFORE_WITHDRAWAL"
            assert (
                params.cancellation_delay > params.withdrawal_delay
            ), "CANCELLATION_DELAY_TOO_SHORT"

            # Source chain timelocks (maker's funds)
            src_withdrawal = sp.add_seconds(
                params.start_time, sp.to_int(params.withdrawal_delay)
            )

            src_public_withdrawal = sp.add_seconds(
                src_withdrawal, sp.to_int(params.public_delay_additional)
            )  # Public withdrawal after source withdrawal

            src_cancellation = sp.add_seconds(
                params.start_time, sp.to_int(params.cancellation_delay)
            )  # Cancellation after source start time

            src_public_cancellation = sp.add_seconds(
                src_cancellation, sp.to_int(params.public_delay_additional)
            )  # Public cancellation after source cancellation

            # Destination chain timelocks (resolver's funds) - earlier than source for atomicity
            # FIXED: Calculate destination times relative to source times with proper buffer
            dst_withdrawal_delay = params.withdrawal_delay - coordination_buffer
            dst_withdrawal = sp.add_seconds(
                params.start_time, dst_withdrawal_delay
            )  # Must be before src_cancellation
            dst_public_withdrawal = sp.add_seconds(
                dst_withdrawal, sp.to_int(params.public_delay_additional)
            )  # Public withdrawal after destination withdrawal
            dst_cancellation = sp.add_seconds(
                dst_public_withdrawal, sp.to_int(coordination_buffer)
            )  # Cancellation after public withdrawal
            dst_public_cancellation = sp.add_seconds(
                dst_cancellation, sp.to_int(params.public_delay_additional)
            )  # Public cancellation after destination cancellation

            # Create timelock configuration
            timelock_config = sp.record(
                src_withdrawal=src_withdrawal,
                src_public_withdrawal=src_public_withdrawal,
                src_cancellation=src_cancellation,
                src_public_cancellation=src_public_cancellation,
                dst_withdrawal=dst_withdrawal,
                dst_public_withdrawal=dst_public_withdrawal,
                dst_cancellation=dst_cancellation,
                dst_public_cancellation=dst_public_cancellation,
                coordination_buffer=coordination_buffer,
                gas_adjustment_factor=params.gas_adjustment_factor,
            )

            # Validate timelock sequence
            self.validate_timelock_sequence(timelock_config)

            # Store configuration
            self.data.active_timelocks[params.order_hash] = timelock_config
            self.data.total_timelock_configs += 1

            # Emit timelock configuration event
            sp.emit(
                sp.record(
                    order_hash=params.order_hash,
                    src_withdrawal=src_withdrawal,
                    src_cancellation=src_cancellation,
                    dst_withdrawal=dst_withdrawal,
                    dst_cancellation=dst_cancellation,
                    coordination_buffer=coordination_buffer,
                ),
                tag="timelocks_calculated",
            )

        @sp.entrypoint
        def adjust_timelocks_for_gas(self, params):
            """
            Adjust timelocks based on current gas prices
            """
            sp.cast(params, sp.record(order_hash=sp.bytes, new_gas_price=t_nat))

            # Get existing timelock configuration
            assert self.data.active_timelocks.contains(
                params.order_hash
            ), "TIMELOCK_CONFIG_NOT_FOUND"
            config = self.data.active_timelocks[params.order_hash]

            # Calculate gas price ratio and adjustment
            assert self.data.current_gas_price > 0, "INVALID_BASE_GAS_PRICE"

            gas_ratio = sp.nat(0)
            gas_ratio_result = sp.ediv(
                params.new_gas_price * 10000, self.data.current_gas_price
            )
            if gas_ratio_result.is_some():
                gas_ratio = sp.fst(gas_ratio_result.unwrap_some())

            # Calculate time adjustment based on gas price change
            # Higher gas -> faster confirmation -> shorter timelocks
            # Lower gas -> slower confirmation -> longer timelocks
            adjustment_seconds = sp.nat(0)

            if gas_ratio > 10000:  # Gas price increased
                # Reduce timelock by up to factor percentage
                max_reduction = sp.nat(0)
                max_reduction_result = sp.ediv(
                    config.gas_adjustment_factor * config.coordination_buffer, 10000
                )
                if max_reduction_result.is_some():
                    max_reduction = sp.fst(max_reduction_result.unwrap_some())

                gas_multiplier = sp.nat(0)
                gas_multiplier_result = sp.ediv(gas_ratio, 100)  # Convert to percentage
                if gas_multiplier_result.is_some():
                    gas_multiplier = sp.fst(gas_multiplier_result.unwrap_some())

                adjustment_seconds = min(max_reduction, gas_multiplier)
            else:  # Gas price decreased
                # Increase timelock by up to factor percentage
                max_increase = sp.nat(0)
                max_increase_result = sp.ediv(
                    config.gas_adjustment_factor * config.coordination_buffer, 10000
                )
                if max_increase_result.is_some():
                    max_increase = sp.fst(max_increase_result.unwrap_some())

                gas_multiplier = sp.nat(0)
                gas_multiplier_result = sp.ediv(
                    10000 * gas_ratio, 100
                )  # Convert to percentage
                if gas_multiplier_result.is_some():
                    gas_multiplier = sp.fst(gas_multiplier_result.unwrap_some())

                adjustment_seconds = min(max_increase, gas_multiplier)

            # FIXED: Apply adjustments while maintaining ordering
            # Add verification to ensure safe adjustment
            assert (
                adjustment_seconds <= config.coordination_buffer
            ), "ADJUSTMENT_TOO_LARGE"

            # Adjust base times first
            new_src_withdrawal = config.src_withdrawal
            new_src_cancellation = config.src_cancellation

            if gas_ratio > 10000:  # Reduce timelocks
                # FIXED: Use signed seconds instead of negative nat
                new_src_withdrawal = sp.add_seconds(
                    config.src_withdrawal, -sp.to_int(adjustment_seconds)
                )
                new_src_cancellation = sp.add_seconds(
                    config.src_cancellation, -sp.to_int(adjustment_seconds)
                )
            else:  # Increase timelocks
                new_src_withdrawal = sp.add_seconds(
                    config.src_withdrawal, sp.to_int(adjustment_seconds)
                )
                new_src_cancellation = sp.add_seconds(
                    config.src_cancellation, sp.to_int(adjustment_seconds)
                )

            # FIXED: Recompute dependent timelock stages to maintain ordering
            # Public withdrawal = withdrawal + public_delay
            original_public_delay = config.src_public_withdrawal - config.src_withdrawal

            new_src_public_withdrawal = sp.add_seconds(
                new_src_withdrawal, original_public_delay
            )

            # Public cancellation = cancellation + public_delay
            original_public_cancel_delay = (
                config.src_public_cancellation - config.src_cancellation
            )
            new_src_public_cancellation = sp.add_seconds(
                new_src_cancellation, original_public_cancel_delay
            )

            # Update configuration with proper ordering preserved
            updated_config = sp.record(
                dst_withdrawal=config.dst_withdrawal,
                dst_public_withdrawal=config.dst_public_withdrawal,
                dst_cancellation=config.dst_cancellation,
                dst_public_cancellation=config.dst_public_cancellation,
                coordination_buffer=config.coordination_buffer,
                gas_adjustment_factor=config.gas_adjustment_factor,
                # Update the specific fields to change
                src_withdrawal=new_src_withdrawal,
                src_public_withdrawal=new_src_public_withdrawal,  # FIXED: Recomputed
                src_cancellation=new_src_cancellation,
                src_public_cancellation=new_src_public_cancellation,  # FIXED: Recomputed
            )

            self.data.active_timelocks[params.order_hash] = updated_config

            # Validate the adjusted sequence still makes sense
            self.validate_timelock_sequence(updated_config)

            # Store updated configuration
            self.data.active_timelocks[params.order_hash] = updated_config
            self.data.current_gas_price = params.new_gas_price

            # Emit adjustment event
            sp.emit(
                sp.record(
                    order_hash=params.order_hash,
                    old_gas_price=self.data.current_gas_price,
                    new_gas_price=params.new_gas_price,
                    adjustment_seconds=adjustment_seconds,
                    gas_ratio=gas_ratio,
                ),
                tag="timelocks_adjusted",
            )

        @sp.entrypoint
        def store_compact_timelock(self, params):
            """
            Store timelock in compact format for gas efficiency

            Reduces storage costs by using offsets from base time.
            """
            sp.cast(
                params,
                sp.record(
                    order_hash=sp.bytes,
                    base_time=t_timestamp,
                    withdrawal_offset=t_nat,
                    public_withdrawal_offset=t_nat,
                    cancellation_offset=t_nat,
                    public_cancellation_offset=t_nat,
                    is_source_chain=t_bool,
                ),
            )

            # Validate offset sequence
            assert (
                params.withdrawal_offset <= params.public_withdrawal_offset
            ), "INVALID_WITHDRAWAL_OFFSETS"
            assert (
                params.public_withdrawal_offset <= params.cancellation_offset
            ), "INVALID_CANCELLATION_OFFSETS"
            assert (
                params.cancellation_offset <= params.public_cancellation_offset
            ), "INVALID_PUBLIC_OFFSETS"

            # Create compact timelock
            compact_timelock = sp.record(
                base_time=params.base_time,
                withdrawal_offset=params.withdrawal_offset,
                public_withdrawal_offset=params.public_withdrawal_offset,
                cancellation_offset=params.cancellation_offset,
                public_cancellation_offset=params.public_cancellation_offset,
                is_source_chain=params.is_source_chain,
            )

            self.data.compact_timelocks[params.order_hash] = compact_timelock

            sp.emit(
                sp.record(
                    order_hash=params.order_hash,
                    base_time=params.base_time,
                    is_source_chain=params.is_source_chain,
                ),
                tag="compact_stored",
            )

        # ================================================================
        # VALIDATION FUNCTIONS
        # ================================================================

        @sp.private
        def validate_timelock_sequence(self, config):
            """
            Validate that timelock sequence maintains atomicity

            Critical: dst_withdrawal < src_cancellation for atomic swap security.
            """
            sp.cast(config, timelock_config_type)

            # Source chain sequence validation
            assert (
                config.src_withdrawal <= config.src_public_withdrawal
            ), "INVALID_SRC_WITHDRAWAL_SEQUENCE"
            assert (
                config.src_public_withdrawal <= config.src_cancellation
            ), "INVALID_SRC_CANCELLATION_SEQUENCE"
            assert (
                config.src_cancellation <= config.src_public_cancellation
            ), "INVALID_SRC_PUBLIC_SEQUENCE"

            # Destination chain sequence validation
            assert (
                config.dst_withdrawal <= config.dst_public_withdrawal
            ), "INVALID_DST_WITHDRAWAL_SEQUENCE"
            assert (
                config.dst_public_withdrawal <= config.dst_cancellation
            ), "INVALID_DST_CANCELLATION_SEQUENCE"
            assert (
                config.dst_cancellation <= config.dst_public_cancellation
            ), "INVALID_DST_PUBLIC_SEQUENCE"

            # Cross-chain atomicity validation (most critical)
            assert (
                config.dst_withdrawal < config.src_cancellation
            ), "ATOMICITY_VIOLATION"

            # Ensure reasonable time gaps
            assert (
                config.coordination_buffer >= 300
            ), "COORDINATION_BUFFER_TOO_SHORT"  # Min 5 minutes
            assert (
                config.coordination_buffer <= 3600
            ), "COORDINATION_BUFFER_TOO_LONG"  # Max 1 hour

        # ================================================================
        # VIEW FUNCTIONS
        # ================================================================

        @sp.onchain_view
        def get_timelock_config(self, order_hash):
            """Get full timelock configuration for an order"""
            sp.cast(order_hash, sp.bytes)

            assert self.data.active_timelocks.contains(
                order_hash
            ), "TIMELOCK_CONFIG_NOT_FOUND"
            config = self.data.active_timelocks[order_hash]

            return config

        @sp.onchain_view
        def expand_compact_timelock(self, order_hash):
            """Expand compact timelock back to full timestamps"""
            sp.cast(order_hash, sp.bytes)

            assert self.data.compact_timelocks.contains(
                order_hash
            ), "COMPACT_TIMELOCK_NOT_FOUND"
            compact = self.data.compact_timelocks[order_hash]

            # Expand offsets back to full timestamps
            withdrawal = sp.add_seconds(
                compact.base_time, sp.to_int(compact.withdrawal_offset)
            )
            public_withdrawal = sp.add_seconds(
                compact.base_time, sp.to_int(compact.public_withdrawal_offset)
            )
            cancellation = sp.add_seconds(
                compact.base_time, sp.to_int(compact.cancellation_offset)
            )
            public_cancellation = sp.add_seconds(
                compact.base_time, sp.to_int(compact.public_cancellation_offset)
            )

            return sp.record(
                withdrawal=withdrawal,
                public_withdrawal=public_withdrawal,
                cancellation=cancellation,
                public_cancellation=public_cancellation,
                is_source_chain=compact.is_source_chain,
                base_time=compact.base_time,
            )

        @sp.onchain_view
        def is_timelock_expired(self, params):
            """Check if specific timelock stage has expired"""
            sp.cast(
                params,
                sp.record(
                    order_hash=sp.bytes,
                    stage=sp.string,  # "withdrawal", "public_withdrawal", "cancellation", "public_cancellation"
                ),
            )

            assert self.data.active_timelocks.contains(
                params.order_hash
            ), "TIMELOCK_CONFIG_NOT_FOUND"
            config = self.data.active_timelocks[params.order_hash]

            is_expired = False

            if params.stage == "withdrawal":
                is_expired = sp.now >= config.src_withdrawal
            if params.stage == "public_withdrawal":
                is_expired = sp.now >= config.src_public_withdrawal
            if params.stage == "cancellation":
                is_expired = sp.now >= config.src_cancellation
            if params.stage == "public_cancellation":
                is_expired = sp.now >= config.src_public_cancellation

            return is_expired

        # ================================================================
        # ADMIN FUNCTIONS
        # ================================================================

        @sp.entrypoint
        def update_default_coordination_buffer(self, new_buffer):
            """Update default coordination buffer (admin only)"""
            sp.cast(new_buffer, t_nat)
            assert sp.sender == self.data.admin, "ADMIN_ONLY"
            assert new_buffer >= 300, "BUFFER_TOO_SHORT"  # Min 5 minutes
            assert new_buffer <= 3600, "BUFFER_TOO_LONG"  # Max 1 hour

            old_buffer = self.data.default_coordination_buffer
            self.data.default_coordination_buffer = new_buffer

            sp.emit(
                sp.record(
                    old_buffer=old_buffer, new_buffer=new_buffer, updated_by=sp.sender
                ),
                tag="buffer_updated",
            )


def bytes_of_string(s):
    return sp.bytes("0x" + s.encode("utf-8").hex())


if "main" in __name__:
    # ================================================================
    # TESTING
    # ================================================================

    @sp.add_test()
    def test_timelocks_lib_fixed():
        """Test fixed timelock functionality"""

        # Test accounts
        admin = sp.test_account("admin")
        maker = sp.test_account("maker")

        # Deploy timelock library
        scenario = sp.test_scenario("TimelockLib Fixed Tests")
        timelock_lib = TimelockLib.TimelockLibContract(admin=admin.address)
        scenario += timelock_lib

        # Test 1: Calculate cross-chain timelocks
        scenario.h2("Test 1: Calculate Cross-Chain Timelocks")

        order_hash = bytes_of_string("test_order_123")
        base_time = sp.timestamp(1000)

        timelock_lib.calculate_cross_chain_timelocks(
            sp.record(
                order_hash=order_hash,
                start_time=base_time,
                withdrawal_delay=900,  # 15 minutes
                cancellation_delay=1800,  # 30 minutes
                public_delay_additional=600,  # 10 minutes additional
                gas_adjustment_factor=500,  # 5% max adjustment
            ),
            _sender=maker,
            _now=base_time,
        )

        # Test 2: Gas adjustment (FIXED: now maintains ordering)
        scenario.h2("Test 2: Gas-Adjusted Timelocks")

        timelock_lib.adjust_timelocks_for_gas(
            sp.record(
                order_hash=order_hash, new_gas_price=1500  # 50% higher gas price
            ),
            _sender=maker,
            _now=base_time.add_seconds(100),
        )
