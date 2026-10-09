#![no_std]
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, Address, BytesN, Env, Symbol, Vec,
};

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub enum Role {
    Monitor,
    Responder,
}

#[derive(Clone, Debug)]
#[contracttype]
pub struct Flag {
    pub agent: Address,
    pub score: u32,
    pub ledger: u32,
}

#[derive(Clone, Debug)]
#[contracttype]
pub struct PendingUpgrade {
    pub wasm_hash: BytesN<32>,
    pub executable_at: u32,
}

#[contracttype]
pub enum DataKey {
    Admin,
    Agent(Address),
    RiskThreshold,
    Flags(Address),
    PendingUpgrade,
    Paused,
    PendingAdmin,
}

const FLAG_EVENT: Symbol = symbol_short!("flagged");
const MAX_FLAGS_PER_SUBJECT: u32 = 50;
/// Ledgers that must pass between proposing and executing an upgrade (~1 day).
pub const UPGRADE_DELAY_LEDGERS: u32 = 17_280;

#[contract]
pub struct SoroWatch;

#[contractimpl]
impl SoroWatch {
    /// One-time setup. Sets the contract admin and a default risk threshold.
    pub fn initialize(env: Env, admin: Address, default_threshold: u32) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::RiskThreshold, &default_threshold);
    }

    /// Admin-only: authorize an address as a Monitor or Responder agent.
    /// Monitors can observe but not flag; only Responders can call flag_anomaly.
    pub fn authorize_agent(env: Env, admin: Address, agent: Address, role: Role) {
        admin.require_auth();
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized");
        if stored_admin != admin {
            panic!("unauthorized");
        }
        env.storage().instance().set(&DataKey::Agent(agent), &role);
    }

    /// Admin-only: remove an agent's role so it can no longer flag anomalies.
    /// Panics if the agent has no role.
    pub fn revoke_agent(env: Env, admin: Address, agent: Address) {
        admin.require_auth();
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized");
        if stored_admin != admin {
            panic!("unauthorized");
        }
        let key = DataKey::Agent(agent.clone());
        if !env.storage().instance().has(&key) {
            panic!("agent not found");
        }
        env.storage().instance().remove(&key);
        env.events().publish((symbol_short!("revoked"), agent), ());
    }

    /// Admin-only: propose a new contract WASM. It can only be executed after
    /// UPGRADE_DELAY_LEDGERS have passed, giving users time to react.
    pub fn propose_upgrade(env: Env, admin: Address, wasm_hash: BytesN<32>) {
        Self::require_admin(&env, &admin);
        let pending = PendingUpgrade {
            wasm_hash,
            executable_at: env.ledger().sequence() + UPGRADE_DELAY_LEDGERS,
        };
        env.storage()
            .instance()
            .set(&DataKey::PendingUpgrade, &pending);
        env.events()
            .publish((symbol_short!("upg_prop"),), pending.executable_at);
    }

    /// Admin-only: cancel a pending upgrade.
    pub fn cancel_upgrade(env: Env, admin: Address) {
        Self::require_admin(&env, &admin);
        if !env.storage().instance().has(&DataKey::PendingUpgrade) {
            panic!("no pending upgrade");
        }
        env.storage().instance().remove(&DataKey::PendingUpgrade);
        env.events().publish((symbol_short!("upg_canc"),), ());
    }

    /// Admin-only: apply the pending upgrade once the delay has passed.
    pub fn execute_upgrade(env: Env, admin: Address) {
        Self::require_admin(&env, &admin);
        let pending: PendingUpgrade = env
            .storage()
            .instance()
            .get(&DataKey::PendingUpgrade)
            .expect("no pending upgrade");
        if env.ledger().sequence() < pending.executable_at {
            panic!("upgrade delay not elapsed");
        }
        env.storage().instance().remove(&DataKey::PendingUpgrade);
        env.deployer()
            .update_current_contract_wasm(pending.wasm_hash);
    }

    /// Admin-only: start handing over the admin role. Nothing changes until
    /// `new_admin` calls `accept_admin`, so a typo in the address cannot lock
    /// the contract out. Proposing again replaces the earlier proposal.
    pub fn propose_admin(env: Env, admin: Address, new_admin: Address) {
        Self::require_admin(&env, &admin);
        env.storage()
            .instance()
            .set(&DataKey::PendingAdmin, &new_admin);
        env.events()
            .publish((symbol_short!("adm_prop"),), new_admin);
    }

    /// Called by the proposed admin to take over. The previous admin loses
    /// the role immediately.
    pub fn accept_admin(env: Env, new_admin: Address) {
        new_admin.require_auth();
        let pending: Address = env
            .storage()
            .instance()
            .get(&DataKey::PendingAdmin)
            .expect("no pending admin");
        if pending != new_admin {
            panic!("not the pending admin");
        }
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        env.storage().instance().remove(&DataKey::PendingAdmin);
        env.events()
            .publish((symbol_short!("adm_xfer"),), new_admin);
    }

    /// Admin-only: cancel a pending admin transfer.
    pub fn cancel_admin_transfer(env: Env, admin: Address) {
        Self::require_admin(&env, &admin);
        if !env.storage().instance().has(&DataKey::PendingAdmin) {
            panic!("no pending admin");
        }
        env.storage().instance().remove(&DataKey::PendingAdmin);
        env.events().publish((symbol_short!("adm_canc"),), ());
    }

    pub fn get_pending_admin(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::PendingAdmin)
    }

    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized")
    }

    /// Admin-only: pause flagging, e.g. while investigating a faulty agent.
    /// Reads and admin actions keep working while paused.
    pub fn pause(env: Env, admin: Address) {
        Self::require_admin(&env, &admin);
        env.storage().instance().set(&DataKey::Paused, &true);
        env.events().publish((symbol_short!("paused"),), ());
    }

    /// Admin-only: resume flagging after a pause.
    pub fn unpause(env: Env, admin: Address) {
        Self::require_admin(&env, &admin);
        env.storage().instance().remove(&DataKey::Paused);
        env.events().publish((symbol_short!("unpaused"),), ());
    }

    pub fn is_paused(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false)
    }

    pub fn get_pending_upgrade(env: Env) -> Option<PendingUpgrade> {
        env.storage().instance().get(&DataKey::PendingUpgrade)
    }

    pub fn get_role(env: Env, agent: Address) -> Option<Role> {
        env.storage().instance().get(&DataKey::Agent(agent))
    }

    /// Called by an authorized Responder agent to flag a subject address.
    /// Persists the flag (capped at MAX_FLAGS_PER_SUBJECT, oldest dropped)
    /// and emits an event for off-chain services to consume.
    pub fn flag_anomaly(env: Env, agent: Address, subject: Address, score: u32) {
        agent.require_auth();
        if Self::is_paused(env.clone()) {
            panic!("contract is paused");
        }
        let role: Option<Role> = env.storage().instance().get(&DataKey::Agent(agent.clone()));
        match role {
            Some(Role::Responder) => {}
            _ => panic!("caller is not an authorized responder"),
        }

        let mut flags: Vec<Flag> = env
            .storage()
            .persistent()
            .get(&DataKey::Flags(subject.clone()))
            .unwrap_or(Vec::new(&env));

        if flags.len() >= MAX_FLAGS_PER_SUBJECT {
            flags.remove(0);
        }
        flags.push_back(Flag {
            agent: agent.clone(),
            score,
            ledger: env.ledger().sequence(),
        });
        env.storage()
            .persistent()
            .set(&DataKey::Flags(subject.clone()), &flags);

        env.events().publish((FLAG_EVENT, agent, subject), score);
    }

    /// Read the flag history for a subject address.
    pub fn get_flags(env: Env, subject: Address) -> Vec<Flag> {
        env.storage()
            .persistent()
            .get(&DataKey::Flags(subject))
            .unwrap_or(Vec::new(&env))
    }

    pub fn get_threshold(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::RiskThreshold)
            .unwrap_or(0)
    }
}

impl SoroWatch {
    fn require_admin(env: &Env, admin: &Address) {
        admin.require_auth();
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized");
        if stored_admin != *admin {
            panic!("unauthorized");
        }
    }
}

mod test;
