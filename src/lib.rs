#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env, Symbol, Vec};

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

#[contracttype]
pub enum DataKey {
    Admin,
    Agent(Address),
    RiskThreshold,
    Flags(Address),
}

const FLAG_EVENT: Symbol = symbol_short!("flagged");
const MAX_FLAGS_PER_SUBJECT: u32 = 50;

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

    pub fn get_role(env: Env, agent: Address) -> Option<Role> {
        env.storage().instance().get(&DataKey::Agent(agent))
    }

    /// Called by an authorized Responder agent to flag a subject address.
    /// Persists the flag (capped at MAX_FLAGS_PER_SUBJECT, oldest dropped)
    /// and emits an event for off-chain services to consume.
    pub fn flag_anomaly(env: Env, agent: Address, subject: Address, score: u32) {
        agent.require_auth();
        let role: Option<Role> = env
            .storage()
            .instance()
            .get(&DataKey::Agent(agent.clone()));
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

mod test;
