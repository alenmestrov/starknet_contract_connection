use starknet::core::types::Felt;
use starknet::core::codec::{Encode, Error, FeltWriter};
use serde::{Serialize, Deserialize};
use hex;

pub type ContextId = Felt;

// Context Member ID
pub type ContextIdentity = Felt;

#[derive(Debug, Encode)]
pub struct Signed {
    pub payload: Vec<Felt>,
    pub signature_r: Felt,
    pub signature_s: Felt,
}

#[derive(Debug, Encode)]
pub struct Request {
    pub kind: RequestKind,
    pub signer_id: ContextIdentity,
    pub nonce: u64,
}

#[derive(Debug, Serialize, Deserialize, Encode)]
pub enum RequestKind {
    Context(ContextRequest),
}

#[derive(Debug, Serialize, Deserialize, Encode)]
pub struct ContextRequest {
    pub context_id: ContextId,
    pub kind: ContextRequestKind,
}

#[derive(Debug, Serialize, Deserialize, Encode)]
pub enum ContextRequestKind {
    Add(ContextIdentity, Application),
}

// Context Application
#[derive(Debug, Serialize, Deserialize, Clone, Encode)]
pub struct Application {
    pub id: Felt,
    pub blob: Felt,
    pub size: u64,
    pub source: EncodableString,
    pub metadata: EncodableString
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncodableString(pub String);

impl Encode for EncodableString {
    fn encode<W: FeltWriter>(&self, writer: &mut W) -> Result<(), Error> {
        const WORD_SIZE: usize = 31;
        let bytes = self.0.as_bytes();
        
        // Calculate full words and pending word
        let full_words_count = bytes.len() / WORD_SIZE;
        let pending_len = bytes.len() % WORD_SIZE;
        
        // Write number of full words
        writer.write(Felt::from(full_words_count));
        
        // Write full words (31 chars each)
        for i in 0..full_words_count {
            let start = i * WORD_SIZE;
            let word_bytes = &bytes[start..start + WORD_SIZE];
            let word_hex = hex::encode(word_bytes);
            writer.write(Felt::from_hex(&format!("0x{}", word_hex)).unwrap());
        }
        
        // Write pending word if exists
        if pending_len > 0 {
            let pending_bytes = &bytes[full_words_count * WORD_SIZE..];
            let pending_hex = hex::encode(pending_bytes);
            writer.write(Felt::from_hex(&format!("0x{}", pending_hex)).unwrap());
        } else {
            writer.write(Felt::ZERO);
        }
        
        // Write pending word length
        writer.write(Felt::from(pending_len));
        
        Ok(())
    }
}
