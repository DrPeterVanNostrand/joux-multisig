//! This file is a model for how Joux's tripartite key-exchange could be used by
//! multi-sig enabled wallets to generate shared secrets. A multi-sig account's
//! shared secret could be utilized to perform 3-of-3 multi-sig transaction
//! signing where each of the three parties involved in Joux's key-exchange must
//! sign a transaction and publish it to the blockchain before the transaction
//! is considered valid.
//!
//! This implementation is a novel (as far as I know) usage of Zcash's pairing
//! enabled curve BLS12-381. Curve BLS12-381 uses the asymmetric pairing:
//! `e(G1, G2) -> Gt`, where `e` is a bilinear-map, `G1` is a point from the
//! the first curve subgroup, `G2` is a point from the second curve subgroup,
//! and `Gt` is an element from the field `Fq12`.
//!
//! Note #1: Joux's one-round key-exchange (as implemented here) is resilient
//! only when faced with passive adversaries, the two-round variant is required
//! for any appreciable level of security.
//!
//! Note #2: Transaction signing and the blockchain are not implemented here.
//! What is implemented is the key-exchange between clients using our
//! fictitious cryptocurrency protocol to establish multi-sig addresses and
//! signing-keys (i.e. "shared secrets").

use pairing::{CurveAffine, CurveProjective, EncodedPoint, Field, PrimeField};
use pairing::bls12_381::{
    G1Affine as G1Elem,
    G1Uncompressed,
    G2Affine as G2Elem,
    Fq12 as GtElem,
    Fr as ScalarFieldElem,
};
use rand::{thread_rng, Rng, ThreadRng};
use sha3::{Digest, Sha3_256};

/// A unique identifier assigned to each `Client` in our cryptocurrency
/// protocol.
type ClientId = usize;

/// Each `Client` is capable of storing multiple accounts in a database. An
/// `AccountId` represents an index in this database that maps to an `Account`
/// instance. `AccountId`s are used internally by each `Client`, they are not
/// used publicly as part of our cryptocurrency protocol.
type AccountId = usize;

/// Represents an address in our cryptocurrency protocol. Each `Account` stored
/// by a `Client` is associated with one address. An `Address` can either be a
/// single-signer address or a mutli-sig address.
type Address = [u8; 32];

/// Represents an address and its associated cryptographic keys for either a
/// single-signer address or a multi-sig address. Each `Client` controls zero or
/// more `Account`s.
///
/// Single-signer accounts (`Account::SingleSig`) are generated using a single
/// key-pair.
///
/// Multi-signature accounts (`Account::MultiSig`) use Joux's one-round
/// tripartite key-exchange protocol to generate a their address and
/// shared-secret (signing-key).
#[derive(Debug)]
enum Account {
    SingleSig {
        sk: ScalarFieldElem,
        pk: G1Elem,
        addr: Address,
    },
    MultiSig {
        sk: ScalarFieldElem,
        pk_g1: G1Elem,
        pk_g2: G2Elem,
        shared_secret: Option<GtElem>,
        addr: Option<Address>,
    },
}

impl Account {
    /// A getter for this account's secret-key.
    fn sk(&self) -> &ScalarFieldElem {
        match self {
            Account::SingleSig { ref sk, .. } => sk,
            Account::MultiSig { ref sk, .. } => sk,
        }
    }

    /// A getter for this account's `G1` public-key.
    fn pk_g1(&self) -> &G1Elem {
        match self {
            Account::SingleSig { ref pk, .. } => pk,
            Account::MultiSig { ref pk_g1, .. } => pk_g1,
        }
    }

    /// A getter for a mutli-sig account's `G2` public-key.
    fn pk_g2(&self) -> &G2Elem {
        match self {
            Account::SingleSig { .. } => {
                panic!(
                    "single signer accounts do not have public-keys from G2"
                );
            }
            Account::MultiSig { ref pk_g2, .. } => pk_g2,
        }
    }

    /// A getter for a multi-sig account's shared secret.
    fn shared_secret(&self) -> &GtElem {
        match self {
            Account::SingleSig { .. } => {
                panic!(
                    "single signer accounts do not have a shared secret"
                );
            }
            Account::MultiSig { ref shared_secret, .. } => {
                shared_secret.as_ref().unwrap()
            }
        }
    }

    /// A getter for this account's address.
    fn addr(&self) -> &Address {
        match self {
            Account::SingleSig { ref addr, .. } => addr,
            Account::MultiSig { ref addr, .. } => addr.as_ref().unwrap(),
        }
    }

    /// A setter for this account's address.
    fn set_address(&mut self, new_addr: Address) {
        match self {
            Account::SingleSig { ref mut addr, .. } => *addr = new_addr,
            Account::MultiSig { ref mut addr, .. } => *addr = Some(new_addr),
        }
    }

    /// A setter for a multi-sig account's shared secret.
    fn set_shared_secret(&mut self, calculated_shared_secret: GtElem) {
        match self {
            Account::SingleSig { .. } => {
                panic!(
                    "cannot set the shared secret for a single signer account"
                );
            }
            Account::MultiSig { ref mut shared_secret, .. } => {
                *shared_secret = Some(calculated_shared_secret);
            }
        }
    }
}

/// Represents a message passed between `Client`s in Joux's one-round tripartite
/// key-exchange. This inter-`Client` message is used to generate a shared
/// secret using curve BLS12-381's pairing.
#[derive(Clone, Copy, Debug)]
struct KeyExchangeMessage {
    client_id: ClientId,
    pk_g1: G1Elem,
    pk_g2: G2Elem,
}

/// Represents a piece of software that implements our fictitious cryptocurrency
/// protocol.
///
/// Each client has a unique identifier (`id`) and an accounts database. A
/// client can store any number of single-signer and multi-sig accounts. Each
/// account in the `accounts` database is associated with an address and a
/// series of cryptographic keys.
#[derive(Debug)]
struct Client {
    id: usize,
    rng: ThreadRng,
    hasher: Sha3_256,
    accounts: Vec<Account>,
}

impl Client {
    fn new() -> Self {
        let mut rng = thread_rng();
        Client {
            id: rng.gen(),
            rng,
            hasher: Sha3_256::new(),
            accounts: vec![],
        }
    }

    fn get_account(&self, account_id: AccountId) -> &Account {
        self
            .accounts
            .get(account_id)
            .expect("account does not exist")
    }

    fn get_mut_account(&mut self, account_id: AccountId) -> &mut Account {
        self
            .accounts
            .get_mut(account_id)
            .expect("account does not exist")
    }

    fn add_account(&mut self, account: Account) -> AccountId {
        self.accounts.push(account);
        self.accounts.len() - 1
    }

    fn create_key_exchange_message(
        &self,
        account_id: AccountId,
    ) -> KeyExchangeMessage {
        let multisig_acct = self.get_account(account_id);
        KeyExchangeMessage {
            client_id: self.id,
            pk_g1: *multisig_acct.pk_g1(),
            pk_g2: *multisig_acct.pk_g2(),
        }
    }

    /// Creates a multi-sig address by concatenating Alice, Bob, and Clara's
    /// encoded G1 public-keys then hashing the result using SHA3-256.
    fn create_multisig_addr(
        &mut self,
        pk1: G1Elem,
        pk2: G1Elem,
        pk3: G1Elem,
    ) -> Address {
        let pk1_encoded = G1Uncompressed::from_affine(pk1);
        let pk2_encoded = G1Uncompressed::from_affine(pk2);
        let pk3_encoded = G1Uncompressed::from_affine(pk3);

        self.hasher.input(&pk1_encoded);
        self.hasher.input(&pk2_encoded);
        self.hasher.input(&pk3_encoded);

        let digest = self.hasher.result_reset();
        let mut addr: Address = [0; 32];
        addr.copy_from_slice(&digest);
        addr
    }

    /// Creates an unfinalized multi-sig account. An unfinalized mutli-sig
    /// account is comprised of a key-triplet (one secret-key and two
    /// public-keys). During Joux's key-exchange, each client finalizes the
    /// multi-sig account created here by calculating the multi-sig account's
    /// address and shared secret.
    fn new_multisig_account(&mut self) -> AccountId {
        let sk: ScalarFieldElem = self.rng.gen();
        let pk_g1 = G1Elem::one().mul(sk.clone()).into_affine();
        let pk_g2 = G2Elem::one().mul(sk.clone()).into_affine();
        let account = Account::MultiSig {
            sk,
            pk_g1,
            pk_g2,
            shared_secret: None,
            addr: None,
        };
        self.add_account(account)
    }

    /// Calculates and sets an multi-sig account's shared secret and address.
    fn create_shared_secret(
        &mut self,
        account_id: AccountId,
        msg1: KeyExchangeMessage,
        msg2: KeyExchangeMessage,
    ) {
        // Our public-key is used to calculate the mutli-sig address.
        let my_pk_g1 = *self.get_account(account_id).pk_g1();

        // The order of the bilinear-map's arguments is determined by the
        // client-ids of each of the parties involved in the key-exchange. The
        // following procedure is used to determine the order of the arguments
        // in the pairing:
        //
        // - If I am Alice, use Bob's public-key as the first pairing argument.
        // - Else if I am Bob, use Clara's public-key as the first pairing
        // argument.
        // - Else if I am Clara, use Alice's public-key as the first pairing
        // argument.
        //
        // Note that the pairing used in Joux's key-exchange is given by:
        // `e(G1, G2) -> Gt`. Below we determine which client's public-key is
        // used for `G1` and which is used for `G2`. The output of the pairing,
        // `Gt`, is the shared secret.
        let i_am_alice = self.id < msg1.client_id && self.id < msg2.client_id;
        let i_am_clara = self.id > msg1.client_id && self.id > msg2.client_id;

        let (pk_g1, pk_g2, addr) = if i_am_alice {
            let party1_is_bob = msg1.client_id < msg2.client_id;
            if party1_is_bob {
                let addr = self.create_multisig_addr(
                    my_pk_g1,
                    msg1.pk_g1,
                    msg2.pk_g1,
                );
                (msg1.pk_g1, msg2.pk_g2, addr)
            } else {
                let addr = self.create_multisig_addr(
                    my_pk_g1,
                    msg2.pk_g1,
                    msg1.pk_g1,
                );
                (msg2.pk_g1, msg1.pk_g2, addr)
            }
        } else if i_am_clara {
            let party1_is_alice = msg1.client_id < msg2.client_id;
            if party1_is_alice {
                let addr = self.create_multisig_addr(
                    msg1.pk_g1,
                    msg2.pk_g1,
                    my_pk_g1,
                );
                (msg1.pk_g1, msg2.pk_g2, addr)
            } else {
                let addr = self.create_multisig_addr(
                    msg2.pk_g1,
                    msg1.pk_g1,
                    my_pk_g1,
                );
                (msg2.pk_g1, msg1.pk_g2, addr)
            }
        } else {
            let party1_is_clara = msg1.client_id > msg2.client_id;
            if party1_is_clara {
                let addr = self.create_multisig_addr(
                    msg2.pk_g1,
                    my_pk_g1,
                    msg1.pk_g1,
                );
                (msg1.pk_g1, msg2.pk_g2, addr)
            } else {
                let addr = self.create_multisig_addr(
                    msg1.pk_g1,
                    my_pk_g1,
                    msg2.pk_g1,
                );
                (msg2.pk_g1, msg1.pk_g2, addr)
            }
        };

        // Calculate the multi-sig account's shared secret.
        let sk = self.get_account(account_id).sk().into_repr();
        let shared_secret = pk_g1.pairing_with(&pk_g2).pow(sk);

        // Set the multi-sig account's shared secret and address.
        let multisig_acct = self.get_mut_account(account_id);
        multisig_acct.set_shared_secret(shared_secret);
        multisig_acct.set_address(addr);
    }
}

fn main() {
    // Create three clients, each will participate in the creation of a
    // multi-sig account.
    let mut alice = Client::new();
    let mut bob = Client::new();
    let mut clara = Client::new();

    // Each party creates a new unfinalized multi-sig account.
    let alice_acct_id = alice.new_multisig_account();
    let bob_acct_id = bob.new_multisig_account();
    let clara_acct_id = clara.new_multisig_account();

    // Each party creates its key-exchange message.
    let alice_msg = alice.create_key_exchange_message(alice_acct_id);
    let bob_msg = bob.create_key_exchange_message(bob_acct_id);
    let clara_msg = clara.create_key_exchange_message(clara_acct_id);

    // Each party broadcasts their key-exchange message and calculates the
    // multi-sig account's shared secret and address.
    alice.create_shared_secret(alice_acct_id, bob_msg, clara_msg);
    bob.create_shared_secret(bob_acct_id, clara_msg, alice_msg);
    clara.create_shared_secret(clara_acct_id, alice_msg, bob_msg);

    // Assert that all three parties have generated the same mutli-sig address
    // and shared secret.
    assert_eq!(
        alice.get_account(alice_acct_id).addr(),
        bob.get_account(bob_acct_id).addr()
    );
    assert_eq!(
        alice.get_account(alice_acct_id).addr(),
        clara.get_account(clara_acct_id).addr()
    );
    assert_eq!(
        alice.get_account(alice_acct_id).shared_secret(),
        bob.get_account(bob_acct_id).shared_secret()
    );
    assert_eq!(
        alice.get_account(alice_acct_id).shared_secret(),
        clara.get_account(clara_acct_id).shared_secret()
    );
}
