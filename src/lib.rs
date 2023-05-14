#[macro_use]
extern crate pamsm;

use std::{
    fs::File,
    io::{BufRead, BufReader},
};

use anyhow::{ensure, Context, Result};
use data_encoding::BASE64_MIME;
use pamsm::{Pam, PamError, PamFlags, PamServiceModule};

use thrussh_keys::{agent::client::AgentClient, key::PublicKey};
use tokio::runtime::Runtime;

struct PamSSHAgent;

fn authenticate(args: Vec<String>) -> Result<bool> {
    ensure!(
        args.len() == 1,
        "Exactly one argument: path to authorized_keys file; found {:?}",
        args
    );

    let pubkeys = {
        let pubkey_file = File::open(&args[0]).context("opening pk file")?;
        let mut keys = vec![];
        for line in BufReader::new(pubkey_file).lines() {
            let line = line.context("reading pk file")?;
            if line.trim().is_empty() {
                continue;
            }
            let parts = line.split_whitespace().collect::<Vec<_>>();
            ensure!(parts.len() > 1);
            let key = BASE64_MIME
                .decode(parts[1].as_bytes())
                .context("parsing public key")?;
            let pk = PublicKey::parse(parts[0].as_bytes(), &key).context("parsing public key")?;
            keys.push(pk);
        }
        keys
    };

    let random_bytes: Vec<_> = (0..1024).map(|_| rand::random::<u8>()).collect();

    let runtime = Runtime::new()?;
    runtime.block_on(async move {
        let mut agent = AgentClient::connect_env().await?;
        let agent_ids = agent.request_identities().await?;
        for id in agent_ids {
            if !pubkeys.contains(&id) {
                continue;
            }
            let sig;
            (agent, sig) = agent.sign_request_signature(&id, &random_bytes).await;
            let sig = match sig {
                Ok(sig) => sig,
                Err(_) => continue,
            };
            if id.verify_detached(&random_bytes, sig.as_ref()) {
                return Ok(true);
            } else {
                eprintln!("Invalid signature from agent, signature does not verify");
            }
        }
        Ok(false)
    })
}

impl PamServiceModule for PamSSHAgent {
    fn authenticate(_: Pam, _: PamFlags, args: Vec<String>) -> PamError {
        let auth_result = authenticate(args);
        match auth_result {
            Ok(b) => {
                if b {
                    PamError::SUCCESS
                } else {
                    PamError::AUTH_ERR
                }
            }
            Err(e) => {
                eprintln!("Authentication failure: {:?}", e);
                PamError::ABORT
            }
        }
    }
}

pam_module!(PamSSHAgent);
