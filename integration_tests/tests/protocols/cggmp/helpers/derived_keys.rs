use super::dkg_sign::{run_dkg, sign_t_2};
use anyhow::Result;
use polysig_driver::{bip32::DerivationPath, cggmp};

pub async fn run_dkg_derived_2_2(
    server: &str,
    server_public_key: Vec<u8>,
) -> Result<()> {
    let t = 2;
    let n = 2;
    let (server, mut key_shares, signers) =
        run_dkg(t, n, server, server_public_key).await?;

    let path: DerivationPath = "m/0/2/1/4/2".parse()?;
    for share in &mut key_shares {
        let derived_key = cggmp::derive_bip32(share, &path)?;
        *share = derived_key;
    }

    sign_t_2(t, n, server, key_shares, signers).await?;

    Ok(())
}
