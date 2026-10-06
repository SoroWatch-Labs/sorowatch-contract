#![cfg(test)]
use super::*;
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::BytesN;

fn setup(env: &Env) -> (Address, Address) {
    let contract_id = env.register(SoroWatch, ());
    let admin = Address::generate(env);
    (contract_id, admin)
}

#[test]
fn test_initialize_and_threshold() {
    let env = Env::default();
    env.mock_all_auths();
    let (contract_id, admin) = setup(&env);
    let client = SoroWatchClient::new(&env, &contract_id);

    client.initialize(&admin, &75);
    assert_eq!(client.get_threshold(), 75);
}

#[test]
#[should_panic(expected = "already initialized")]
fn test_double_initialize_panics() {
    let env = Env::default();
    env.mock_all_auths();
    let (contract_id, admin) = setup(&env);
    let client = SoroWatchClient::new(&env, &contract_id);

    client.initialize(&admin, &75);
    client.initialize(&admin, &90);
}

#[test]
fn test_responder_can_flag() {
    let env = Env::default();
    env.mock_all_auths();
    let (contract_id, admin) = setup(&env);
    let client = SoroWatchClient::new(&env, &contract_id);
    client.initialize(&admin, &50);

    let agent = Address::generate(&env);
    let subject = Address::generate(&env);
    client.authorize_agent(&admin, &agent, &Role::Responder);

    client.flag_anomaly(&agent, &subject, &80);

    let flags = client.get_flags(&subject);
    assert_eq!(flags.len(), 1);
    assert_eq!(flags.get(0).unwrap().score, 80);
}

#[test]
#[should_panic(expected = "caller is not an authorized responder")]
fn test_monitor_cannot_flag() {
    let env = Env::default();
    env.mock_all_auths();
    let (contract_id, admin) = setup(&env);
    let client = SoroWatchClient::new(&env, &contract_id);
    client.initialize(&admin, &50);

    let agent = Address::generate(&env);
    let subject = Address::generate(&env);
    client.authorize_agent(&admin, &agent, &Role::Monitor);

    // Monitors are not allowed to flag — this must panic.
    client.flag_anomaly(&agent, &subject, &80);
}

#[test]
#[should_panic(expected = "caller is not an authorized responder")]
fn test_unauthorized_address_cannot_flag() {
    let env = Env::default();
    env.mock_all_auths();
    let (contract_id, admin) = setup(&env);
    let client = SoroWatchClient::new(&env, &contract_id);
    client.initialize(&admin, &50);

    let stranger = Address::generate(&env);
    let subject = Address::generate(&env);

    client.flag_anomaly(&stranger, &subject, &80);
}

#[test]
fn test_multiple_flags_for_same_subject() {
    let env = Env::default();
    env.mock_all_auths();
    let (contract_id, admin) = setup(&env);
    let client = SoroWatchClient::new(&env, &contract_id);
    client.initialize(&admin, &50);

    let agent = Address::generate(&env);
    let subject = Address::generate(&env);
    client.authorize_agent(&admin, &agent, &Role::Responder);

    client.flag_anomaly(&agent, &subject, &60);
    client.flag_anomaly(&agent, &subject, &70);
    client.flag_anomaly(&agent, &subject, &95);

    let flags = client.get_flags(&subject);
    assert_eq!(flags.len(), 3);
    assert_eq!(flags.get(2).unwrap().score, 95);
}

#[test]
fn test_flag_history_caps_and_drops_oldest() {
    let env = Env::default();
    env.mock_all_auths();
    let (contract_id, admin) = setup(&env);
    let client = SoroWatchClient::new(&env, &contract_id);
    client.initialize(&admin, &50);

    let agent = Address::generate(&env);
    let subject = Address::generate(&env);
    client.authorize_agent(&admin, &agent, &Role::Responder);

    for i in 0..(MAX_FLAGS_PER_SUBJECT + 5) {
        client.flag_anomaly(&agent, &subject, &i);
    }

    let flags = client.get_flags(&subject);
    assert_eq!(flags.len(), MAX_FLAGS_PER_SUBJECT);
    // Oldest entries (score 0-4) should have been dropped.
    assert_eq!(flags.get(0).unwrap().score, 5);
}

#[test]
fn test_get_role_returns_none_for_unknown_address() {
    let env = Env::default();
    env.mock_all_auths();
    let (contract_id, _admin) = setup(&env);
    let client = SoroWatchClient::new(&env, &contract_id);

    let stranger = Address::generate(&env);
    assert_eq!(client.get_role(&stranger), None);
}

#[test]
fn test_revoke_agent_removes_role() {
    let env = Env::default();
    env.mock_all_auths();
    let (contract_id, admin) = setup(&env);
    let client = SoroWatchClient::new(&env, &contract_id);
    client.initialize(&admin, &50);

    let agent = Address::generate(&env);
    client.authorize_agent(&admin, &agent, &Role::Responder);
    assert_eq!(client.get_role(&agent), Some(Role::Responder));

    client.revoke_agent(&admin, &agent);
    assert_eq!(client.get_role(&agent), None);
}

#[test]
#[should_panic(expected = "caller is not an authorized responder")]
fn test_revoked_agent_cannot_flag() {
    let env = Env::default();
    env.mock_all_auths();
    let (contract_id, admin) = setup(&env);
    let client = SoroWatchClient::new(&env, &contract_id);
    client.initialize(&admin, &50);

    let agent = Address::generate(&env);
    let subject = Address::generate(&env);
    client.authorize_agent(&admin, &agent, &Role::Responder);
    client.revoke_agent(&admin, &agent);

    client.flag_anomaly(&agent, &subject, &80);
}

#[test]
#[should_panic(expected = "unauthorized")]
fn test_non_admin_cannot_revoke() {
    let env = Env::default();
    env.mock_all_auths();
    let (contract_id, admin) = setup(&env);
    let client = SoroWatchClient::new(&env, &contract_id);
    client.initialize(&admin, &50);

    let agent = Address::generate(&env);
    let attacker = Address::generate(&env);
    client.authorize_agent(&admin, &agent, &Role::Responder);

    client.revoke_agent(&attacker, &agent);
}

#[test]
#[should_panic(expected = "agent not found")]
fn test_revoke_unknown_agent_panics() {
    let env = Env::default();
    env.mock_all_auths();
    let (contract_id, admin) = setup(&env);
    let client = SoroWatchClient::new(&env, &contract_id);
    client.initialize(&admin, &50);

    let stranger = Address::generate(&env);
    client.revoke_agent(&admin, &stranger);
}

fn init(env: &Env) -> (SoroWatchClient<'_>, Address) {
    env.mock_all_auths();
    let (contract_id, admin) = setup(env);
    let client = SoroWatchClient::new(env, &contract_id);
    client.initialize(&admin, &50);
    (client, admin)
}

#[test]
fn test_propose_upgrade_stores_pending() {
    let env = Env::default();
    let (client, admin) = init(&env);
    let hash = BytesN::from_array(&env, &[7u8; 32]);

    assert!(client.get_pending_upgrade().is_none());
    client.propose_upgrade(&admin, &hash);

    let pending = client.get_pending_upgrade().unwrap();
    assert_eq!(pending.wasm_hash, hash);
    assert_eq!(
        pending.executable_at,
        env.ledger().sequence() + UPGRADE_DELAY_LEDGERS
    );
}

#[test]
#[should_panic(expected = "unauthorized")]
fn test_non_admin_cannot_propose_upgrade() {
    let env = Env::default();
    let (client, _admin) = init(&env);
    let attacker = Address::generate(&env);
    client.propose_upgrade(&attacker, &BytesN::from_array(&env, &[1u8; 32]));
}

#[test]
#[should_panic(expected = "upgrade delay not elapsed")]
fn test_execute_before_delay_panics() {
    let env = Env::default();
    let (client, admin) = init(&env);
    client.propose_upgrade(&admin, &BytesN::from_array(&env, &[2u8; 32]));
    client.execute_upgrade(&admin);
}

#[test]
#[should_panic(expected = "no pending upgrade")]
fn test_execute_without_proposal_panics() {
    let env = Env::default();
    let (client, admin) = init(&env);
    client.execute_upgrade(&admin);
}

#[test]
fn test_cancel_upgrade_clears_pending() {
    let env = Env::default();
    let (client, admin) = init(&env);
    client.propose_upgrade(&admin, &BytesN::from_array(&env, &[3u8; 32]));
    client.cancel_upgrade(&admin);
    assert!(client.get_pending_upgrade().is_none());
}

#[test]
#[should_panic(expected = "no pending upgrade")]
fn test_cancel_without_proposal_panics() {
    let env = Env::default();
    let (client, admin) = init(&env);
    client.cancel_upgrade(&admin);
}

#[test]
#[should_panic(expected = "unauthorized")]
fn test_non_admin_cannot_cancel_upgrade() {
    let env = Env::default();
    let (client, admin) = init(&env);
    client.propose_upgrade(&admin, &BytesN::from_array(&env, &[4u8; 32]));
    let attacker = Address::generate(&env);
    client.cancel_upgrade(&attacker);
}

#[test]
fn test_delay_constant_passes_after_ledgers_advance() {
    let env = Env::default();
    let (client, admin) = init(&env);
    client.propose_upgrade(&admin, &BytesN::from_array(&env, &[5u8; 32]));
    let pending = client.get_pending_upgrade().unwrap();

    env.ledger()
        .with_mut(|l| l.sequence_number = pending.executable_at);
    assert!(env.ledger().sequence() >= pending.executable_at);
}
