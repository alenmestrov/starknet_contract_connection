use std::str::FromStr;

use starknet::accounts::{Account, ExecutionEncoding, SingleOwnerAccount};
use starknet::core::chain_id;
use starknet::core::utils::get_selector_from_name;
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::{JsonRpcClient, Url};
use starknet::core::types::{BlockId, BlockTag, Call, Felt, FunctionCall};
use starknet::signers::{LocalWallet, SigningKey};
use starknet_crypto::poseidon_hash_many;
use starknet::core::codec::Encode;
use starknet::providers::Provider;

mod types;
// use crate::types::*;

use crate::types::{Signed, Request, RequestKind, ContextRequest, ContextRequestKind, Application, EncodableString};

// use cainome::rs::abigen;
// abigen!(ContextConfig, "contract/abi.json", output_path("src/types.rs")); 

#[tokio::main]
async fn main() {

    let contract_address = "0x2ce0e808c359df2171ab7807871c548a096d49efe36f6e822ed5523197e9428";
    let relayer_pk = Felt::from_str("0x3466a2196c72a94edd80c49baaad89c3cd71815038c31e1d3c94337ad97406d").unwrap();
    let relayer_sk = SigningKey::from_secret_scalar(relayer_pk);
    
    let alice_key = SigningKey::from_secret_scalar(Felt::from_str("0x402c8f500dd3e61d7405c239e973437fa3e1a45f2e643c470c163a0197153ee").unwrap());
    let alice_public_key = alice_key.verifying_key();
    let alice_public_key_felt = alice_public_key.scalar();
    println!("alice_public_key_felt: {:?}", alice_public_key_felt);
    // let alice_public_key_felt_hex = alice_key.secret_scalar();

    let context_key = SigningKey::from_secret_scalar(Felt::from_str("0x263c2d10461dcbe87a324e9426b6e001e2ff816ed4aec72a1ee2605dcb501b9").unwrap());
    let context_public_key = context_key.verifying_key();
    let context_public_key_felt = context_public_key.scalar();
    println!("context_public_key_felt: {:?}", context_public_key_felt);

    let request = Request {
        signer_id: context_public_key_felt,
        nonce: 0,
        kind: RequestKind::Context(
            ContextRequest {
                context_id: context_public_key_felt,
                kind: ContextRequestKind::Add(
                  alice_public_key_felt,
                  Application {
                      id: Felt::from_str("0x1234567890abcdef1234567890abcdef123456789").unwrap(),
                      blob: Felt::from_str("0x1234567890abcdef1234567890abcdef123456789").unwrap(),
                      size: 0,
                      source: EncodableString("https://calimero.network".to_string()),
                      metadata: EncodableString("Some metadata".to_string()),
                  }
              )
            }
        ),
    };
    
    let mut serialized_request = vec![];
    let _ = request.encode(&mut serialized_request).unwrap();
    println!("serialized_request: {:?}", serialized_request);
    // First hash (equivalent to poseidon_hash_span)
    let first_hash = poseidon_hash_many(&serialized_request);
    
    // Second hash (equivalent to PoseidonTrait::new().update_with(...).finalize())
    let hash = poseidon_hash_many(&[first_hash]);

    let signature = context_key.sign(&hash).unwrap();

    let signed_request = Signed {
        payload: serialized_request,
        signature_r: signature.r,
        signature_s: signature.s,
    };

    println!("signed_request: {:?}", signed_request);

    let mut signed_request_serialized = vec![];
    let _ = signed_request.encode(&mut signed_request_serialized).unwrap();

    println!("signed_request_serialized: {:?}", signed_request_serialized);

    //Call the contract
    let provider = JsonRpcClient::new(HttpTransport::new(
        Url::parse("https://starknet-sepolia.public.blastapi.io/rpc/v0_7").unwrap(),
    ));

    let wallet_pk = LocalWallet::from(relayer_sk);
    let wallet_address =
        Felt::from_hex("0x55d0c6f18991cebbf0dee233cafdd19f906f387a364b040c71c00094355e281")
            .unwrap();
    let mut account = SingleOwnerAccount::new(
        provider.clone(),
        wallet_pk,
        wallet_address,
        chain_id::SEPOLIA,
        ExecutionEncoding::New,
    );
    println!("signed_request_serialized: {:?}", signed_request_serialized);
    account.set_block_id(BlockId::Tag(BlockTag::Pending));

    let result = account
      .execute_v1(vec![Call {
          to: Felt::from_str(contract_address).unwrap(),
          selector: get_selector_from_name("mutate").unwrap(),
          calldata: signed_request_serialized,
      }])
      .send()
      .await
      .unwrap();

    println!("Result: {:?}", result);

    let function_call = FunctionCall {
        contract_address: Felt::from_str(contract_address).unwrap(),
        entry_point_selector: get_selector_from_name("application").unwrap(),
        calldata: vec![context_public_key_felt],
    };

    let result = provider.call(&function_call, BlockId::Tag(BlockTag::Latest)).await;
    println!("{:?}", result);
}
