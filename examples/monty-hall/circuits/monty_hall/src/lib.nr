//! Monty Hall game logic for the PSS round circuits.
//!
//! `game_state` is the state the rounds transition; `door` is the
//! player's door as a secret-shared input and the commitment the contract
//! pins it to.
pub mod door;
pub mod game_state;
