pub mod notes;

use aztec::macros::aztec;

/// Monty Hall over private shared state (PSS): an MPC network is the host.
/// It holds the game state (which door wins) as secret shares that no
/// single party sees, and proves every change with a collaborative
/// UltraHonk ZK proof (a co-SNARK) that this contract verifies in-circuit
/// through `pss_contract::apply`. The player requests every network
/// round; the operator sends the transactions that seed and start the
/// game (`init_game`, `start_game`); the player commits a door, submits
/// the host's rounds, and so verifies the opened door and the result in
/// the player's own PXE.
///
/// Trust model: semi-honest MPC (collusion of the nodes reveals the
/// state); the chain trusts only the proofs, never the operator.
///
/// Where each piece of state lives (docs/DECISIONS.md, "Where state lives on
/// Aztec":
/// single-reader state in PXE notes owned by the reader, many-reader state
/// as a hash anchor, MPC-held state in the sidecar):
/// - the seed and the game state are network-held notes (slots
///   `SEED_SLOT` and `GAME_STATE_SLOT`, domain separators inside the
///   note-hash preimage, agreed with the circuits; no storage is
///   allocated). Their state records are client-held and owned by the
///   player, whose requester key signs every round from `pss_seed` on, so
///   the player carries both, and clients mine their nonces from the
///   transactions' effects;
/// - the `Config` is read only by the operator, so it is a
///   `PrivateImmutable` note the operator owns;
/// - the `Game` (the pins the player's calls use) is read only by the
///   player, so it is a note the player owns, created by start_game;
/// - the player's door and switch choices are `PrivateImmutable` notes the
///   player owns (`notes.nr`).
/// No value has two readers, so nothing is anchored and no call takes a
/// preimage or a nonce as an argument.
///
/// Ordering is enforced by notes and single-use nullifiers, with no phase
/// variable:
/// - `init_game` pushes a single-use nullifier, so it runs once per
///   deployment, and creates the operator's `Config`;
/// - `start_game` reads the caller's `Config`, so nothing but the
///   operator's call runs it and only after `init_game`; it spends the seed
///   note, so it runs once, and creates the player's `Game`;
/// - `choose_door`, `open_door`, `switch_door` and `finish_game` read the
///   caller's `Game`, so only the player calls them and only after
///   `start_game`;
/// - `open_door` spends the game state `start_game` created and reads the
///   player's door note; `finish_game` spends the game state `open_door`
///   created and reads the switch note. A stale game state re-derives a
///   spent nullifier;
/// - `choose_door` and `switch_door` each initialise a `PrivateImmutable`,
///   whose initialisation nullifier makes them single-use;
/// - the round circuits assert the phase stored in the game state, so
///   `finish_game` cannot be proven before `open_door`: the contract alone
///   does not stop that order, since both spend a game-state note.
/// One order is deliberately left open: `switch_door` may precede
/// `choose_door` and `open_door`. It only commits the player earlier and
/// cannot change the result: the winning door comes from the seed fixed in
/// `init_game`, and the stick/switch payoff does not depend on which door
/// was opened.
///
/// No initializer, so the macros emit no initialisation
/// check and no call can be failed by the contract's init state; every
/// call reads only its caller's own notes. The reads use aztec-nr's
/// `get_note`, which fails the call when the note is missing. Only the
/// owner's own transaction reads each note and only this contract's calls
/// create them, so no other party can make a read fail: total_aztec's
/// `get_note_or` (a flag instead of a failure) is for reads another
/// party's state can break, and a flag here would only be asserted.
#[aztec]
pub contract MontyHall {
    use crate::notes::{Config, DoorNote, Game, SwitchNote};

    use aztec::macros::{functions::external, storage::storage};
    use aztec::messages::delivery::MessageDelivery;
    use aztec::note::lifecycle::create_note;
    use aztec::protocol::address::AztecAddress;
    use aztec::state_vars::{Owned, PrivateImmutable, StateVariable};
    use pss_contract::{apply, apply_seed, PssConfig, PssEffects, push_once};

    // The keys: these slots are the request keys of the
    // machine ($state_keys.reads / $state_keys.writes) and the storage slots in the
    // network-held note hashes; the contract passes them as in_slots /
    // out_slots, so a proof over other keys is rejected. Both keys are
    // client-held (see the manifests).
    global SEED_SLOT: Field = 0xff01;
    global GAME_STATE_SLOT: Field = 0xff02;

    // The once-nullifier's domain separator and salt:
    // DOM_SEP__MH_ONCE = 0x4d480005 ("MH" + index) and ONCE_INIT = 1, so
    // init_game pushes the constant `P2(0x4d480005, [1])`
    // (`pss_contract::once_nullifier`). The separator serves this purpose
    // only: a separator shared with another hash of the contract would let
    // one step's nullifier collide with, and so block, the other
    // (pss_contract/src/anchor.nr); the only other separator the contract
    // defines is 0x4d480003, the door commitment (`notes.nr`). ONCE_INIT
    // names which once-only step the flag is for; a second once-only step
    // would take another value under the same separator. The
    // nullifier is public and deterministic (the protocol silos it to the
    // deployment's address), so anyone can see that init_game ran; changing
    // either value only changes the flag of a new deployment, but in an
    // upgrade of a live one it would let init_game run a second time.
    global DOM_SEP__MH_ONCE: u32 = 0x4d480005;
    global ONCE_INIT: Field = 1;

    /// Every piece of single-reader state is a note its
    /// reader owns. `PrivateImmutable` writes each once per owner (its
    /// initialisation nullifier is derived from the owner's nullifier key,
    /// so unlike a once-nullifier it does not label the owner's
    /// transactions), and reading it in a later call is an ordinary note
    /// read request. A game that let the player change a choice would need
    /// `PrivateMutable` and a rule for which choice the round uses.
    #[storage]
    struct Storage<Context> {
        config: Owned<PrivateImmutable<Config, Context>, Context>,
        game: Owned<PrivateImmutable<Game, Context>, Context>,
        door_choice: Owned<PrivateImmutable<DoorNote, Context>, Context>,
        switch_choice: Owned<PrivateImmutable<SwitchNote, Context>, Context>,
    }

    /// Seed the game (the `pss_seed` proof) and record the operator's
    /// Config. The caller becomes the operator. Once per deployment.
    ///
    /// Why the once-nullifier: the Config's
    /// `PrivateImmutable` initialisation nullifier is per (slot, owner):
    /// it stops the same operator from initialising twice, but another
    /// account would derive another nullifier and could seed and start a
    /// second game on this deployment, whose start_game would create a
    /// second `Game` note at the player's slot (see start_game: that note
    /// has no initialisation nullifier). The constant once-nullifier makes
    /// the deployment single-game, so one seed note, one start_game and one
    /// `Game` note exist. It also publicly marks init_game as done, and any
    /// account can be first, so the deployment flow sends init_game from
    /// the same operator right after the deploy, before announcing the
    /// address.
    ///
    /// Nonce-mining indices. Note hashes pushed, in order:
    /// 0 = seed note, 1 = the operator's Config note. Clients mine the seed
    /// note's protocol nonce from this tx's effects by that index; the
    /// operator's PXE finds the Config by note discovery.
    ///
    /// The Config is delivered on chain, unconstrained, to the
    /// operator itself: a constrained delivery would prove nothing the
    /// operator does not already trust, and a lost delivery only stops the
    /// operator's own start_game.
    #[external("private")]
    fn init_game(config: Config, seed_note_hash: Field) {
        assert(config.player != AztecAddress::zero(), "player must not be zero");
        let operator = self.msg_sender();

        apply_seed(
            self.context,
            operator,
            config.seed_vk_hash,
            PssConfig { owner: config.owner, npk_app_hash: config.npk_app_hash },
            SEED_SLOT,
            seed_note_hash,
        );

        push_once(self.context, DOM_SEP__MH_ONCE, ONCE_INIT);
        self.storage.config.at(operator).initialize(config).deliver(
            MessageDelivery::onchain_unconstrained(),
        );
    }

    /// Create the game from the seed (the `monty_hall_init` proof): the
    /// network spends the seed note and stores a game state whose winning
    /// door it derives from the seed, so nobody knows it. Operator only:
    /// the call reads the caller's Config. It then gives the player the
    /// `Game` note.
    ///
    /// The effects arrive field by field, in `PssEffects` order minus
    /// `app_outputs`: an empty array cannot be a function argument, so a
    /// `PssEffects<1, 1, 0>` argument is not allowed.
    ///
    /// The Game note has no initialisation nullifier.
    /// `PrivateImmutable::initialize` derives that nullifier from the
    /// owner's nullifier key, which the operator's PXE does not hold for
    /// the player, so start_game creates the note at the `PrivateImmutable`
    /// slot directly (`create_note`, owner = the player) and the player
    /// reads it with the `PrivateImmutable` getter. Single creation comes
    /// from the seed instead: start_game spends the one seed note, and
    /// init_game's once-nullifier allows one seed note per deployment.
    /// Consequence: the `PrivateImmutable`'s `is_initialized` reports false
    /// for the Game; use the note itself. A contract whose operator could
    /// create several games would need a slot or note per game (for
    /// example a game id in the Game) instead.
    ///
    /// DEV DECISION: delivery of the player's Game note, default on chain
    /// and unconstrained; the operator is trusted for liveness (it could
    /// equally not call start_game), so a constrained delivery would buy
    /// nothing, and a lost delivery only stops the player's own calls.
    /// Design guide: "Verifiable delivery". The delivery's wallet
    /// prerequisites, read from the pinned PXE and
    /// aztec-nr (the e2e's monty-two-wallets scenario, operator and player
    /// in separate PXEs, confirms the first case and the last point):
    /// - the player's PXE must find the note's tag. An operator wallet
    ///   without a tagging hook does not hold the player's keys, so its PXE
    ///   tags through a non-interactive handshake with the standard
    ///   handshake registry, inside this call, and the player's PXE
    ///   discovers the handshake in its sync; the player registers nothing;
    /// - an operator wallet whose hook picks the address-derived (operator,
    ///   player) secret is found only by a PXE that knows the operator as a
    ///   sender, so the player's wallet setup registers the operator's
    ///   address as a sender when it learns the deployment. A sender registered after start_game is mined still
    ///   finds the note: the PXE scans a new sender's tags from index 0, at
    ///   the player's next call. One wallet holding both accounts tags a
    ///   self-send with this secret and scans its own accounts anyway;
    /// - the operator's PXE needs the player's address only. The note hash
    ///   takes the owner as a field, and the encryption and the tag use the
    ///   point derived from the address; aztec-nr's `get_public_keys`, which
    ///   fails for an account the PXE has not registered, is reached only
    ///   by a note's nullifier and by `PrivateImmutable::initialize`,
    ///   neither of which start_game runs. Both would also need the
    ///   player's nullifier key, which no PXE but the player's holds: the
    ///   reason start_game uses create_note (above).
    ///
    /// Nonce-mining indices. Note hashes pushed, in order:
    /// 0 = game-state note, 1 = the player's Game note (found by the
    /// player's PXE); an operator PXE that tags through a handshake adds
    /// its handshake note.
    #[external("private")]
    fn start_game(
        read_leaves: [Field; 1],
        nullifiers: [Field; 1],
        new_note_hashes: [Field; 1],
        npk_app_hash: Field,
    ) {
        let operator = self.msg_sender();
        let config = self.storage.config.at(operator).get_note();

        apply(
            self.context,
            operator,
            config.init_vk_hash,
            PssConfig { owner: config.owner, npk_app_hash: config.npk_app_hash },
            [SEED_SLOT],
            [GAME_STATE_SLOT],
            [],
            PssEffects { read_leaves, nullifiers, new_note_hashes, npk_app_hash, app_outputs: [] },
        );

        let game = Game {
            owner: config.owner,
            npk_app_hash: config.npk_app_hash,
            open_vk_hash: config.open_vk_hash,
            finish_vk_hash: config.finish_vk_hash,
        };
        create_note(self.context, config.player, self.storage.game.get_storage_slot(), game)
            .deliver(MessageDelivery::onchain_unconstrained());
    }

    /// The player commits a door as a note only the player can read. The
    /// chain sees the commitment's leaf; the door and `randomness` stay in
    /// the player's PXE, and go to the network only as INPUT_SHARED shares
    /// in open_door. Player only, after start_game: the call reads the
    /// caller's Game.
    ///
    /// Nonce-mining indices. Note hashes pushed, in order:
    /// 0 = door note. The player's PXE finds it by note discovery, so no
    /// client mines this nonce.
    ///
    /// The note is delivered on chain, unconstrained. The
    /// player sends it to itself, so a constrained delivery would prove
    /// nothing the player does not already trust; a lost delivery only
    /// costs the player its own game.
    #[external("private")]
    fn choose_door(door: u8, randomness: Field) {
        assert(door < 3, "door out of range");
        let player = self.msg_sender();
        let _ = self.storage.game.at(player).get_note();

        self.storage.door_choice.at(player).initialize(DoorNote { door, randomness }).deliver(
            MessageDelivery::onchain_unconstrained(),
        );
    }

    /// The host opens a door (the `monty_hall_open_door` proof): the
    /// network spends the game state, plays the player's door (received as
    /// INPUT_SHARED shares, never in the clear), opens a door that is
    /// neither the player's nor the winner, and stores the next state.
    /// The player submits it, so the proof carrying `opened_door`
    /// (`effects.app_outputs[0]`) is verified in the player's own PXE.
    ///
    /// The door pin: the circuit outputs the commitment of
    /// the door it played as `effects.app_outputs[1]`; the contract reads
    /// the player's door note (a read request on its leaf) and requires
    /// that commitment to equal the note's, so the network played the
    /// committed door. Without it a player could have the network play a
    /// door other than the committed one.
    ///
    /// Nonce-mining indices. Note hashes pushed, in order:
    /// 0 = next game-state note.
    #[external("private")]
    fn open_door(effects: PssEffects<1, 1, 2>) {
        let player = self.msg_sender();
        let game = self.storage.game.at(player).get_note();
        // BRICK path = sidecar (pss_contract::apply): the player's own private function verifies the
        // round and applies its effects. Alternatives: tip (with node-held state: client-held state is
        // the sidecar path's). docs/design-guide/BRICKS.md#path

        apply(
            self.context,
            player,
            game.open_vk_hash,
            PssConfig { owner: game.owner, npk_app_hash: game.npk_app_hash },
            [GAME_STATE_SLOT],
            [GAME_STATE_SLOT],
            [],
            effects,
        );

        let door = self.storage.door_choice.at(player).get_note();
        assert_eq(effects.app_outputs[1], door.commitment(), "not the committed door");
    }

    /// The player commits stick (false) or switch (true), as a note only
    /// the player can read; finish_game reads it. Player only, after
    /// start_game: the call reads the caller's Game.
    ///
    /// Nonce-mining indices. Note hashes pushed, in order:
    /// 0 = switch note, found by the player's PXE.
    ///
    /// The switch note is delivered on chain, unconstrained,
    /// for choose_door's reason: the player sends it to itself, so a
    /// constrained delivery would prove nothing the player does not already
    /// trust. A lost delivery only costs the player its own game: the
    /// initialisation nullifier is spent, so the choice cannot be made
    /// again, and finish_game cannot read the note.
    #[external("private")]
    fn switch_door(switch: bool) {
        let player = self.msg_sender();
        let _ = self.storage.game.at(player).get_note();

        self.storage.switch_choice.at(player).initialize(SwitchNote { switch }).deliver(
            MessageDelivery::onchain_unconstrained(),
        );
    }

    /// The host reveals the result (the `monty_hall_finish` proof): the
    /// network spends the game state and applies stick or switch. `win` is
    /// `app_outputs[0]`, verified in the player's PXE and otherwise
    /// unused. Nothing replaces the state: the game is over.
    ///
    /// The effects arrive field by field, in `PssEffects` order minus
    /// `new_note_hashes`: W = 0, and an empty array cannot be a function
    /// argument.
    ///
    /// The switch binding: the finish circuit's public app
    /// input is `switch`; the contract takes it from the player's switch
    /// note, never from an argument, so the network applies the committed
    /// strategy. The player can therefore not evaluate both strategies on
    /// chain; the machine's `once` consume policy on this round stops it
    /// off chain.
    ///
    /// Nonce-mining indices: no note hashes are pushed.
    #[external("private")]
    fn finish_game(
        read_leaves: [Field; 1],
        nullifiers: [Field; 1],
        npk_app_hash: Field,
        app_outputs: [Field; 1],
    ) {
        let player = self.msg_sender();
        let game = self.storage.game.at(player).get_note();
        let switch = self.storage.switch_choice.at(player).get_note().switch;

        apply(
            self.context,
            player,
            game.finish_vk_hash,
            PssConfig { owner: game.owner, npk_app_hash: game.npk_app_hash },
            [GAME_STATE_SLOT],
            [],
            [switch as Field],
            PssEffects { read_leaves, nullifiers, new_note_hashes: [], npk_app_hash, app_outputs },
        );
    }
}
