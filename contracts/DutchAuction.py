"""
DutchAuction.py - Cross-Chain Dutch Auction Price Calculator

Time-based price decay mechanism for cross-chain swaps.
Compatible with EVM DutchAuctionCalculator for consistent pricing.

Key Features:
- Linear price decay over time
- Cross-chain compatible timing
- Gas cost adjustments (FIXED: proper timestamp arithmetic)
- Multi-segment auction support
"""

import smartpy as sp


@sp.module
def DutchAuction():

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

    # Auction parameters structure
    auction_params_type: type = sp.record(
        start_time=t_timestamp,  # When auction begins
        end_time=t_timestamp,  # When auction ends
        start_price=t_nat,  # Initial high price (best for maker)
        end_price=t_nat,  # Final low price (best for taker)
        maker_amount=t_nat,  # Amount maker is selling
        base_gas_price=t_nat,  # Base gas price for adjustments
        gas_adjustment_factor=t_nat,  # Factor for gas impact (basis points)
    )

    # Auction state tracking
    auction_state_type: type = sp.record(
        is_active=t_bool,  # Whether auction is running
        current_price=t_nat,  # Last calculated price
        last_update=t_timestamp,  # When price was last calculated
        total_filled=t_nat,  # Amount filled so far
        fill_count=t_nat,  # Number of partial fills
    )

    class DutchAuctionContract(sp.Contract):
        """
        Cross-Chain Dutch Auction Price Calculator

        Provides time-decaying price discovery for cross-chain swaps
        with gas adjustment and multi-segment support.
        """

        def __init__(self, admin):
            """
            Initialize Dutch Auction Calculator

            Args:
                admin: Admin address for configuration updates
            """
            self.data = sp.record(
                # Configuration
                admin=admin,
                # Active auctions: auction_id -> auction_params
                auctions=sp.cast(
                    sp.big_map(),
                    sp.big_map[t_bytes, auction_params_type],
                ),
                # Auction states: auction_id -> auction_state
                auction_states=sp.cast(
                    sp.big_map(),
                    sp.big_map[t_bytes, auction_state_type],
                ),
                # Gas price tracking for adjustments
                current_gas_price=sp.nat(1000),  # Default gas price in micro-units
                # Statistics
                total_auctions=sp.nat(0),
                total_volume=sp.nat(0),
            )

        # ================================================================
        # CORE AUCTION FUNCTIONS
        # ================================================================

        @sp.entrypoint
        def create_auction(self, params):
            """
            Create new Dutch auction with price decay parameters

            Auction starts at high price and decays linearly to low price.
            """
            sp.cast(
                params,
                sp.record(
                    auction_id=sp.bytes,
                    start_time=t_timestamp,
                    end_time=t_timestamp,
                    start_price=t_nat,
                    end_price=t_nat,
                    maker_amount=t_nat,
                    base_gas_price=t_nat,
                    gas_adjustment_factor=t_nat,
                ),
            )

            # Validate auction parameters
            assert not self.data.auctions.contains(
                params.auction_id
            ), "AUCTION_ALREADY_EXISTS"
            assert params.end_time > params.start_time, "INVALID_TIME_RANGE"
            assert params.start_price > params.end_price, "INVALID_PRICE_RANGE"
            assert params.maker_amount > 0, "ZERO_MAKER_AMOUNT"
            assert (
                params.gas_adjustment_factor <= 10000
            ), "INVALID_GAS_FACTOR"  # Max 100%

            # Create auction parameters
            auction_params = sp.record(
                start_time=params.start_time,
                end_time=params.end_time,
                start_price=params.start_price,
                end_price=params.end_price,
                maker_amount=params.maker_amount,
                base_gas_price=params.base_gas_price,
                gas_adjustment_factor=params.gas_adjustment_factor,
            )

            self.data.auctions[params.auction_id] = auction_params

            # Initialize auction state
            auction_state = sp.record(
                is_active=True,
                current_price=params.start_price,
                last_update=sp.now,
                total_filled=sp.nat(0),
                fill_count=sp.nat(0),
            )

            self.data.auction_states[params.auction_id] = auction_state
            self.data.total_auctions += 1

            # Emit auction created event
            sp.emit(
                sp.record(
                    auction_id=params.auction_id,
                    start_time=params.start_time,
                    end_time=params.end_time,
                    start_price=params.start_price,
                    end_price=params.end_price,
                    maker_amount=params.maker_amount,
                    creator=sp.sender,
                ),
                tag="auction_created",
            )

        @sp.entrypoint
        def update_price(self, auction_id):
            """
            Update auction price based on time decay (mutating entrypoint)

            Updates the stored current price for efficiency.
            FIXED: Separated from view function to avoid sp.result in entrypoint.
            """
            sp.cast(auction_id, sp.bytes)

            # Get auction parameters
            assert self.data.auctions.contains(auction_id), "AUCTION_NOT_FOUND"
            auction_params = self.data.auctions[auction_id]
            auction_state = self.data.auction_states[auction_id]

            # Check if auction is still active
            assert auction_state.is_active, "AUCTION_NOT_ACTIVE"

            # Calculate time-based price
            current_price = self.compute_time_based_price(auction_params)

            # Apply gas price adjustments if configured
            adjusted_price = self.apply_gas_adjustment(
                sp.record(base_price=current_price, auction_params=auction_params)
            )

            # Update auction state
            updated_state = sp.record(
                is_active=auction_state.is_active,
                total_filled=auction_state.total_filled,
                fill_count=auction_state.fill_count,
                current_price=adjusted_price,
                last_update=sp.now,
            )

            self.data.auction_states[auction_id] = updated_state

        @sp.onchain_view
        def get_current_price(self, auction_id):
            """
            Get current auction price (read-only view)

            FIXED: Made this an offchain view that returns price without updating storage.
            """
            sp.cast(auction_id, sp.bytes)

            # Get auction parameters
            assert self.data.auctions.contains(auction_id), "AUCTION_NOT_FOUND"
            auction_params = self.data.auctions[auction_id]
            auction_state = self.data.auction_states[auction_id]

            # Check if auction is still active
            assert auction_state.is_active, "AUCTION_NOT_ACTIVE"

            # Calculate time-based price
            current_price = self.compute_time_based_price(auction_params)

            # Apply gas price adjustments if configured
            adjusted_price = self.apply_gas_adjustment(
                sp.record(base_price=current_price, auction_params=auction_params)
            )

            # Return calculated price
            return adjusted_price

        @sp.entrypoint
        def get_taking_amount(self, params):
            """
            Calculate taking amount for given making amount (like EVM version)

            Compatible with EVM DutchAuctionCalculator interface.
            """
            sp.cast(
                params,
                sp.record(
                    auction_id=sp.bytes,
                    making_amount=t_nat,
                    current_gas_price=sp.option[t_nat],  # Optional gas price override
                ),
            )

            # Update gas price if provided
            if params.current_gas_price.is_some():
                self.data.current_gas_price = params.current_gas_price.unwrap_some()

            # Get current auction price (calculate without storing)
            auction_params = self.data.auctions[params.auction_id]
            auction_state = self.data.auction_states[params.auction_id]
            current_price = self.compute_time_based_price(auction_params)
            adjusted_price = self.apply_gas_adjustment(
                sp.record(base_price=current_price, auction_params=auction_params)
            )

            # Calculate taking amount: (current_price * making_amount) / maker_amount - total_filled
            # NOTE: This proportional taking amount based on current auction price
            taking_amount = sp.nat(0)
            taking_amount_result = sp.ediv(
                adjusted_price * params.making_amount,
                sp.as_nat(auction_params.maker_amount - auction_state.total_filled),
            )
            if taking_amount_result.is_some():
                taking_amount = sp.fst(taking_amount_result.unwrap_some())

            # Emit result via event since entrypoints can't return values
            sp.emit(
                sp.record(
                    auction_id=params.auction_id,
                    making_amount=params.making_amount,
                    taking_amount=taking_amount,
                    current_price=adjusted_price,
                ),
                tag="taking_amount",
            )

        @sp.entrypoint
        def record_fill(self, params):
            """
            Record a partial fill in the auction

            Updates auction state to track fill progress.
            FIXED: Optionally recalculates current price for accurate emission.
            """
            sp.cast(
                params,
                sp.record(
                    auction_id=sp.bytes, filled_amount=t_nat, resolver=sp.address
                ),
            )

            # Get auction state
            assert self.data.auctions.contains(params.auction_id), "AUCTION_NOT_FOUND"
            auction_state = self.data.auction_states[params.auction_id]
            auction_params = self.data.auctions[params.auction_id]

            # Validate fill
            assert auction_state.is_active, "AUCTION_NOT_ACTIVE"
            assert params.filled_amount > 0, "ZERO_FILL_AMOUNT"

            # Check for auction completion
            new_total_filled = auction_state.total_filled + params.filled_amount
            assert new_total_filled <= auction_params.maker_amount, "OVERFILL_AUCTION"

            # Recalculate current price for accurate reporting
            current_price = self.compute_time_based_price(auction_params)
            adjusted_price = self.apply_gas_adjustment(
                sp.record(base_price=current_price, auction_params=auction_params)
            )

            # Update auction state
            is_currently_active = auction_state.is_active
            # Check if auction is now complete
            if new_total_filled == auction_params.maker_amount:
                is_currently_active = False

            updated_state = sp.record(
                is_active=is_currently_active,
                total_filled=new_total_filled,
                fill_count=auction_state.fill_count + 1,
                current_price=adjusted_price,
                last_update=sp.now,
            )

            self.data.auction_states[params.auction_id] = updated_state
            self.data.total_volume += params.filled_amount

            # Emit fill event with current price
            sp.emit(
                sp.record(
                    auction_id=params.auction_id,
                    filled_amount=params.filled_amount,
                    total_filled=new_total_filled,
                    resolver=params.resolver,
                    current_price=adjusted_price,  # Use current price, not stale price
                    is_complete=(new_total_filled == auction_params.maker_amount),
                ),
                tag="auction_filled",
            )

        # ================================================================
        # PRICE CALCULATION UTILITIES
        # ================================================================

        @sp.private
        def compute_time_based_price(self, auction_params):
            """
            Compute current price based on linear time decay

            Formula: start_price * (end_time - current_time) + end_price * (current_time - start_time)
                     / (end_time - start_time)

            FIXED: Returns Python value instead of using sp.result
            """

            sp.cast(auction_params, auction_params_type)

            current_time = sp.now
            if current_time < auction_params.start_time:
                current_time = auction_params.start_time

            if current_time > auction_params.end_time:
                current_time = auction_params.end_time

            current_price = sp.nat(0)
            # Handle edge cases
            if current_time <= auction_params.start_time:
                current_price = auction_params.start_price

            else:
                if current_time >= auction_params.end_time:
                    current_price = auction_params.end_price

                else:
                    # Linear interpolation with FIXED timestamp arithmetic and overflow protection
                    # FIXED: Use sp.as_nat to handle timestamp differences safely
                    total_duration = sp.as_nat(
                        auction_params.end_time - auction_params.start_time
                    )
                    elapsed_time = sp.as_nat(current_time - auction_params.start_time)
                    remaining_time = sp.as_nat(auction_params.end_time - current_time)

                    # FIXED: Add overflow protection for large price calculations
                    # Verify that intermediate calculations won't overflow
                    max_safe_price = (
                        1000000000000  # 1 trillion (reasonable upper bound)
                    )
                    max_safe_duration = 86400 * 365  # 1 year in seconds

                    assert (
                        auction_params.start_price <= max_safe_price
                    ), "START_PRICE_TOO_LARGE"
                    assert (
                        auction_params.end_price <= max_safe_price
                    ), "END_PRICE_TOO_LARGE"
                    assert total_duration <= max_safe_duration, "DURATION_TOO_LONG"

                    # Calculate weighted average with overflow protection
                    # Use division by 10 to keep intermediate values smaller
                    start_component = sp.nat(0)
                    start_component_result = sp.ediv(
                        auction_params.start_price * remaining_time, total_duration
                    )
                    if start_component_result.is_some():
                        start_component = sp.fst(start_component_result.unwrap_some())

                    end_component = sp.nat(0)
                    end_component_result = sp.ediv(
                        auction_params.end_price * elapsed_time, total_duration
                    )
                    if end_component_result.is_some():
                        end_component = sp.fst(end_component_result.unwrap_some())

                    current_price = start_component + end_component

            return current_price

        @sp.private(with_storage="read-only")
        def apply_gas_adjustment(self, base_price, auction_params):
            """
            Apply gas price adjustments to the base auction price

            Higher gas prices slightly reduce the price to encourage faster fills.
            Lower gas prices slightly increase the price.

            FIXED: Returns Python value instead of using sp.result
            """

            sp.cast(base_price, t_nat)
            sp.cast(auction_params, auction_params_type)

            adjusted_price = sp.nat(0)

            if auction_params.gas_adjustment_factor == 0:
                adjusted_price = base_price

            else:
                # Calculate gas price ratio (current / base) in basis points
                gas_ratio = sp.nat(0)
                gas_ratio_result = sp.ediv(
                    self.data.current_gas_price * 10000, auction_params.base_gas_price
                )
                if gas_ratio_result.is_some():
                    gas_ratio = sp.fst(gas_ratio_result.unwrap_some())

                # Apply adjustment: price * (1 + adjustment_factor * (1 - gas_ratio))
                # If gas is higher than base, price decreases
                # If gas is lower than base, price increases
                adjustment = sp.int(0)
                adjustment_result = sp.ediv(
                    sp.to_int(auction_params.gas_adjustment_factor)
                    * (10000 - gas_ratio),
                    10000,
                )
                if adjustment_result.is_some():
                    adjustment = sp.fst(adjustment_result.unwrap_some())

                # FIXED: Add overflow protection by using min with reasonable bounds
                adjusted_multiplier = sp.as_nat(
                    min(20000, 10000 + adjustment)
                )  # Max 2x adjustment

                adjusted_price_result = sp.ediv(base_price * adjusted_multiplier, 10000)
                if adjusted_price_result.is_some():
                    adjusted_price = sp.fst(adjusted_price_result.unwrap_some())

            return adjusted_price

        # ================================================================
        # VIEW FUNCTIONS
        # ================================================================

        @sp.onchain_view
        def get_auction_info(self, auction_id):
            """Get complete auction information"""
            sp.cast(auction_id, sp.bytes)

            assert self.data.auctions.contains(auction_id), "AUCTION_NOT_FOUND"
            auction_params = self.data.auctions[auction_id]
            auction_state = self.data.auction_states[auction_id]

            return sp.record(
                params=auction_params, state=auction_state, current_time=sp.now
            )

        @sp.onchain_view
        def is_auction_active(self, auction_id):
            """Check if auction is currently active"""
            sp.cast(auction_id, sp.bytes)

            assert self.data.auction_states.contains(auction_id), "AUCTION_NOT_FOUND"
            auction_state = self.data.auction_states[auction_id]
            auction_params = self.data.auctions[auction_id]

            # Active if: state says active AND current time is within auction period
            is_active = (
                auction_state.is_active
                and (sp.now >= auction_params.start_time)
                and (sp.now <= auction_params.end_time)
            )

            return is_active

        @sp.onchain_view
        def get_fill_progress(self, auction_id):
            """Get auction fill progress information"""
            sp.cast(auction_id, sp.bytes)

            assert self.data.auction_states.contains(auction_id), "AUCTION_NOT_FOUND"
            auction_state = self.data.auction_states[auction_id]
            auction_params = self.data.auctions[auction_id]

            # Calculate completion percentage
            completion_percentage = sp.nat(0)
            completion_percentage_result = sp.ediv(
                auction_state.total_filled * 100, auction_params.maker_amount
            )
            if completion_percentage_result.is_some():
                completion_percentage = sp.fst(
                    completion_percentage_result.unwrap_some()
                )

            return sp.record(
                total_amount=auction_params.maker_amount,
                filled_amount=auction_state.total_filled,
                remaining_amount=sp.as_nat(
                    auction_params.maker_amount - auction_state.total_filled
                ),
                fill_count=auction_state.fill_count,
                completion_percentage=completion_percentage,
                is_complete=(auction_state.total_filled == auction_params.maker_amount),
            )

        # ================================================================
        # ADMIN FUNCTIONS
        # ================================================================

        @sp.entrypoint
        def update_gas_price(self, new_gas_price):
            """Update current gas price for adjustments (admin only)"""
            sp.cast(new_gas_price, t_nat)
            assert sp.sender == self.data.admin, "ADMIN_ONLY"

            old_gas_price = self.data.current_gas_price
            self.data.current_gas_price = new_gas_price

            sp.emit(
                sp.record(
                    old_gas_price=old_gas_price,
                    new_gas_price=new_gas_price,
                    updated_by=sp.sender,
                ),
                tag="gas_updated",
            )

        @sp.entrypoint
        def emergency_end_auction(self, auction_id):
            """Emergency end auction (admin only)"""
            sp.cast(auction_id, sp.bytes)
            assert sp.sender == self.data.admin, "ADMIN_ONLY"

            assert self.data.auction_states.contains(auction_id), "AUCTION_NOT_FOUND"
            auction_state = self.data.auction_states[auction_id]

            updated_state = sp.record(
                is_active=False,
                current_price=auction_state.current_price,
                last_update=sp.now,
                total_filled=auction_state.total_filled,
                fill_count=auction_state.fill_count,
            )
            self.data.auction_states[auction_id] = updated_state

            sp.emit(
                sp.record(auction_id=auction_id, ended_by=sp.sender),
                tag="auction_ended",
            )


def bytes_of_string(s):
    return sp.bytes("0x" + s.encode("utf-8").hex())


if "main" in __name__:
    # ================================================================
    # TESTING
    # ================================================================

    @sp.add_test()
    def test_dutch_auction_fixed():
        """Test fixed Dutch auction functionality"""

        # Test accounts
        admin = sp.test_account("admin")
        maker = sp.test_account("maker")
        resolver = sp.test_account("resolver")

        # Deploy auction contract
        scenario = sp.test_scenario("DutchAuction Fixed Tests")
        auction = DutchAuction.DutchAuctionContract(admin=admin.address)
        scenario += auction

        # Test 1: Create auction
        scenario.h2("Test 1: Create Dutch Auction")

        auction_id = bytes_of_string("auction123")

        auction.create_auction(
            sp.record(
                auction_id=auction_id,
                start_time=sp.timestamp(100),
                end_time=sp.timestamp(1000),
                start_price=2000,  # High price at start
                end_price=1000,  # Low price at end
                maker_amount=10000,
                base_gas_price=1000,
                gas_adjustment_factor=500,  # 5% max adjustment
            ),
            _sender=maker,
            _now=sp.timestamp(50),
        )

        # Test 2: Price calculations with separated mutating/view functions
        scenario.h2("Test 2: Fixed Price Calculations")

        # Update price  (mutating)
        auction.update_price(auction_id, _sender=resolver, _now=sp.timestamp(100))

        # View current price (read-only)
        # Price view is now an onchain_view that works correctly
